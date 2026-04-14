/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 */
#include <rec.h>
#include <rsi-handler.h>
#include <smc-rsi.h>
#include <debug.h>
#include <buffer.h>
#include <granule.h>
#include <realm.h>
#include <s2tt.h>
#include <policy_parser.h>
#include <policy_validator.h>
#include <policy_validator_actions.h>
#include <measurement.h>
#include <rmi_rsi_count.h>
#include <realm_add_meta.h>
#include <sgt.h>

/*
 * Scan [gpa, gpa + size) at PAGE_LEVEL (4 KiB) and:
 *  - count ASSIGNED_NS / UNASSIGNED_NS at PAGE_LEVEL
 *  - if ASSIGNED_NS, unmap it (write UNASSIGNED_NS + invalidate)
 *
 * Caller must hold the RD lock (lock ordering RD -> RTT).
 *
 * Returns: number of pages actually unmapped (ASSIGNED_NS -> UNASSIGNED_NS).
 */
unsigned long rmm_unmap_conflicting_gpas(const struct s2tt_context *s2_ctx,
                                    unsigned long gpa,
                                    unsigned long size)
{
    unsigned long page_size, ipa, end;
    unsigned long unmapped = 0UL, seen_assigned = 0UL, seen_unassigned = 0UL;

    if ((s2_ctx == NULL) || (s2_ctx->g_rtt == NULL) || (size == 0UL)) {
        INFO("unmap_conflicting_gpas: unmapped=0 assigned=0 unassigned=0\n");
        return 0UL;
    }

    page_size = s2tte_map_size(S2TT_PAGE_LEVEL);

    /* Compute end with overflow safety. */
    end = gpa + size;
    if (end < gpa) {
        end = ~0UL;
    }

    /* Page-align bounds (cover any partially covered pages). */
    ipa = gpa & ~(page_size - 1UL);
    end = (end + page_size - 1UL) & ~(page_size - 1UL);

    while (ipa < end) {
        struct s2tt_walk wi;
        unsigned long *table;
        unsigned long s2tte;
        long level;

        granule_lock(s2_ctx->g_rtt, GRANULE_STATE_RTT);
        s2tt_walk_lock_unlock(s2_ctx, ipa, S2TT_PAGE_LEVEL, &wi);
        /* root RTT unlocked, wi.g_llt locked (if non-NULL) */

        if (wi.g_llt == NULL) {
            ipa += page_size;
            continue;
        }

        table = buffer_granule_map(wi.g_llt, SLOT_RTT);
        if (table == NULL) {
            granule_unlock(wi.g_llt);
            break;
        }

        s2tte = s2tte_read(&table[wi.index]);
        level = wi.last_level;

        if (level == S2TT_PAGE_LEVEL) {
            if (s2tte_is_assigned_ns(s2_ctx, s2tte, level)) {
                seen_assigned++;
                s2tte_write(&table[wi.index],
                            s2tte_create_unassigned_ns(s2_ctx));
                s2tt_invalidate_page(s2_ctx, ipa);
                unmapped++;
            } else if (s2tte_is_unassigned_ns(s2_ctx, s2tte)) {
                seen_unassigned++;
            }
        }

        buffer_unmap(table);
        granule_unlock(wi.g_llt);
        ipa += page_size;
    }

    INFO("unmap_conflicting_gpas: range=[0x%lx,0x%lx) unmapped=%lu "
         "assigned_seen=%lu unassigned_seen=%lu\n",
         gpa, gpa + size, unmapped, seen_assigned, seen_unassigned);

    return unmapped;
}

void handle_rsi_upload_policy(struct rec *rec, struct rsi_result *res)
{
    unsigned long ipa = rec->regs[1];
    unsigned long pd_addr;
    enum s2_walk_status walk_status;
    struct s2_walk_result walk_res;
    struct granule *gr;
    uint8_t *page;
    // uint8_t *pd_phys;
    struct parsed_payload cfg, p_read;      /* <-- stack, not pointer */
    int rc;
    struct rd *rd;
    // struct s2tt_context s2_ctx;

    res->action = UPDATE_REC_RETURN_TO_REALM;
    INFO("RSI Upload Policy: ipa=0x%lx\n", ipa);

    if (!GRANULE_ALIGNED(ipa) || !addr_in_rec_par(rec, ipa)) {
        INFO("rsi_upload_policy: ipa not granule aligned\n");
        res->smc_res.x[0] = RSI_ERROR_INPUT;
        return;
    }

    walk_status = realm_ipa_to_pa(rec, ipa, &walk_res);

    if (walk_status == WALK_FAIL) {
        INFO("rsi_upload_policy: WALK_FAIL\n");
        if (walk_res.ripas_val == RIPAS_EMPTY) {
            INFO("rsi_upload_policy: RIPAS_EMPTY\n");
            res->smc_res.x[0] = RSI_ERROR_INPUT;
        } else {
            INFO("rsi_upload_policy: translation fault at level %lu\n",
                 walk_res.rtt_level);
            res->action = STAGE_2_TRANSLATION_FAULT;
            res->rtt_level = walk_res.rtt_level;
        }
        return;
    }

    if (walk_status == WALK_INVALID_PARAMS) {
        INFO("rsi_upload_policy: WALK_INVALID_PARAMS\n");
        res->smc_res.x[0] = RSI_ERROR_INPUT;
        return;
    }

    /* Map Realm data granule to RMM address space */
    gr = find_granule(walk_res.pa);
    page = (uint8_t *)buffer_granule_map(gr, SLOT_RSI_CALL);
    if (page == NULL) {
        INFO("Can't map page\n");
        granule_unlock(walk_res.llt);
        res->smc_res.x[0] = RSI_ERROR_INPUT;
        return;
    }

    rc = parse_payload(page, GRANULE_SIZE, &cfg);
    if (rc != 0) {
        INFO("rsi_upload_policy: parse failed (rc=%d)\n", rc);
        buffer_unmap(page);
        granule_unlock(walk_res.llt);
        res->smc_res.x[0] = RSI_ERROR_INPUT;
        return;
    }

    /* Unmap Realm data granule */
    buffer_unmap(page);
    /* Unlock last level RTT */
    granule_unlock(walk_res.llt);

    /* get PD from RD */
    granule_lock(rec->realm_info.g_rd, GRANULE_STATE_RD);
    rd = buffer_granule_map(rec->realm_info.g_rd, SLOT_RD);
    if (rd == NULL) {
        INFO("RD is NULL\n");
        granule_unlock(rec->realm_info.g_rd);
        res->smc_res.x[0] = RSI_ERROR_INPUT;
        return;
    }
    if (rd->rsi_uploaded_policy == true) {
        INFO("RSI already uploaded!!\n");
        buffer_unmap(rd);
        granule_unlock(rec->realm_info.g_rd);
        res->smc_res.x[0] = RSI_ERROR_INPUT;
        return;
    }
    policy_validator_actions_set_s2_ctx(&rd->s2_ctx, realm_par_size(rd));

    pd_addr = rd->pd;

    if(!upload_cfg(pd_addr, &cfg, GRANULE_STATE_DELEGATED, SLOT_RSI_CALL)){
        INFO("Failed to write cfg: Config at is empty\n");
        policy_validator_actions_clear_s2_ctx();
        buffer_unmap(rd);
        granule_unlock(rec->realm_info.g_rd);
        res->smc_res.x[0] = RSI_ERROR_INPUT;
        return;
    }

    dump_parsed_payload(&cfg);
    //need to add table to add self - then we run checks.
    ram_add_hash_for_pd(cfg.vms[cfg.self_vm_index].hash, pd_addr);
    ram_pretty_print();

    //validate cfg
    rc = validate_and_activate_all_protected(&cfg, pd_addr);
    if (rc != PVAL_OK) {
        INFO("Policy validation failed with code %d\n", rc);
        policy_validator_actions_clear_s2_ctx();
        buffer_unmap(rd);
        granule_unlock(rec->realm_info.g_rd);
        res->smc_res.x[0] = RSI_ERROR_INPUT;
        return;
    }

    //read again in case it is changed
    if(!load_cfg(pd_addr, &p_read, GRANULE_STATE_DELEGATED, SLOT_RSI_CALL)){
        INFO("Failed to read cfg: Config at PA [%lu] is empty\n", pd_addr);
        policy_validator_actions_clear_s2_ctx();
        buffer_unmap(rd);
        granule_unlock(rec->realm_info.g_rd);
        res->smc_res.x[0] = RSI_ERROR_INPUT;
        return;
    }
    dump_parsed_payload(&p_read);
    
	unsigned char *current_measurement = rd->measurement[PD_MEASUREMENT_SLOT];
    void *extend_measurement = &cfg;

    attest_do_extend(&rec->attest_app_data,
            rd->algorithm,
            current_measurement,
            extend_measurement,
            sizeof(cfg),
            current_measurement,
            MAX_MEASUREMENT_SIZE);
    
    rd->rsi_uploaded_policy = true;
    
    policy_validator_actions_clear_s2_ctx();
    buffer_unmap(rd);
    granule_unlock(rec->realm_info.g_rd);
    res->smc_res.x[0] = RSI_SUCCESS;
}
