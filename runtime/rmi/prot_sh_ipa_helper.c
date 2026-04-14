/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 */

#include <buffer.h>
#include <granule.h>
#include <realm.h>
#include <debug.h>
#include <status.h>
#include <measurement.h>
// #include <policy_table.h>
#include <type_rim_rd.h>
#include <policy_parser.h>

/*PROTECTED_SHARED helpers*/

unsigned long unmap_ipa(unsigned long rd_addr,
               unsigned long ipa_addr,
               unsigned long expected_pa_addr /* or 0 to skip check */)
{
    struct granule *g_rd;
    struct rd *rd;
    struct s2tt_context *s2_ctx;
    struct s2tt_walk wi;
    unsigned long *s2tt;
    unsigned long s2tte, pa;
    bool in_par;

    if (!GRANULE_ALIGNED(ipa_addr)) {
        return RMI_ERROR_INPUT;
    }

    g_rd = find_lock_granule(rd_addr, GRANULE_STATE_RD);
    if (!g_rd) return RMI_ERROR_INPUT;

    rd = buffer_granule_map(g_rd, SLOT_RD);
    if (!rd) { granule_unlock(g_rd); return RMI_ERROR_INPUT; }

    // if (!validate_map_addr(ipa_addr, S2TT_PAGE_LEVEL, rd)) {
    //     buffer_unmap(rd);
    //     granule_unlock(g_rd);
    //     return RMI_ERROR_INPUT;
    // }

    s2_ctx = &rd->s2_ctx;
    in_par = addr_in_par(rd, ipa_addr);

    buffer_unmap(rd);

    /* Lock root RTT, release RD */
    granule_lock(s2_ctx->g_rtt, GRANULE_STATE_RTT);
    granule_unlock(g_rd);

    /* Walk to leaf */
    s2tt_walk_lock_unlock(s2_ctx, ipa_addr, S2TT_PAGE_LEVEL, &wi);

    if (wi.last_level != S2TT_PAGE_LEVEL) {
        granule_unlock(wi.g_llt);
        granule_unlock(s2_ctx->g_rtt);   /* IMPORTANT */
        return pack_return_code(RMI_ERROR_RTT, (unsigned char)wi.last_level);
    }

    s2tt = buffer_granule_map(wi.g_llt, SLOT_RTT);
    if (!s2tt) {
        granule_unlock(wi.g_llt);
        granule_unlock(s2_ctx->g_rtt);
        return RMI_ERROR_INPUT;
    }

    s2tte = s2tte_read(&s2tt[wi.index]);

    /* Accept only “assigned” leaf entries you actually want to break */
    if (!s2tte_is_assigned_ram(s2_ctx, s2tte, S2TT_PAGE_LEVEL) &&
        !s2tte_is_assigned_empty(s2_ctx, s2tte, S2TT_PAGE_LEVEL) &&
        !s2tte_is_assigned_destroyed(s2_ctx, s2tte, S2TT_PAGE_LEVEL)) {
        buffer_unmap(s2tt);
        granule_unlock(wi.g_llt);
        granule_unlock(s2_ctx->g_rtt);
        return pack_return_code(RMI_ERROR_RTT, (unsigned char)S2TT_PAGE_LEVEL);
    }

    pa = s2tte_pa(s2_ctx, s2tte, S2TT_PAGE_LEVEL);
    if (expected_pa_addr && (pa != expected_pa_addr)) {
        buffer_unmap(s2tt);
        granule_unlock(wi.g_llt);
        granule_unlock(s2_ctx->g_rtt);
        return RMI_ERROR_INPUT;
    }

    /* Choose the correct unassigned descriptor */
    unsigned long new_s2tte = in_par
        ? s2tte_create_unassigned_destroyed(s2_ctx)
        : s2tte_create_unassigned_ns(s2_ctx); /* or unassigned_empty, depending on your policy */

    s2tte_write(&s2tt[wi.index], new_s2tte);

    /* Break-before-make TLB maintenance */
    s2tt_invalidate_page(s2_ctx, ipa_addr);

    /* Drop table ref */
    atomic_granule_put(wi.g_llt);

    buffer_unmap(s2tt);
    granule_unlock(wi.g_llt);

    /* MUST unlock root RTT */
    granule_unlock(s2_ctx->g_rtt);

    /*
     * Now drop the DATA granule refcount corresponding to that mapping.
     * This is the part you must implement using the same mechanism that
     * mapping used to “get”/increment the ref.
     */
    // data_granule_put(pa);   // (name varies in-tree)

    return RMI_SUCCESS;
}


unsigned long map_ipa_to_pa(unsigned long rd_addr,
                            unsigned long pa_addr,
                            unsigned long ipa_addr,
                            bool *used_any)
{
	struct s2tt_context *s2_ctx;
    struct s2tt_walk wi;
    unsigned long *s2tt;
    unsigned long s2tte;
	struct granule *g_data;
	struct granule *g_rd;
	struct rd *rd;
	unsigned long ret = RMI_SUCCESS;

	if (!GRANULE_ALIGNED(ipa_addr)) {
		return WALK_INVALID_PARAMS;
	}

	g_rd = find_lock_granule(rd_addr, GRANULE_STATE_RD);
	if (g_rd == NULL) {
		return RMI_ERROR_INPUT;
	}
	rd = buffer_granule_map(g_rd, SLOT_RD);
	assert(rd != NULL);

	// g_data = find_lock_granule(pa_addr, GRANULE_STATE_DATA);
	g_data = find_granule(pa_addr);
	if((g_data == NULL) ||
	    (granule_unlocked_state(g_data) != GRANULE_STATE_DATA)) {
		// INFO("Failed to lock data granule %lx\n", pa_addr);
		buffer_unmap(rd);
		granule_unlock(g_rd);
		return RMI_ERROR_INPUT;
	}
	// granule_unlock(g_data);

	s2_ctx = &(rd->s2_ctx);

	if (!s2_ctx) { 
		INFO("s2_ctx is NULL\n"); 
		buffer_unmap(rd);
		granule_unlock(g_rd);
		return 0; 
	}
	if (!s2_ctx->g_rtt) { 
		INFO("g_rtt is NULL (RTT not created)\n"); 
		buffer_unmap(rd);
		granule_unlock(g_rd);
		return 0; 
	}

	granule_lock(s2_ctx->g_rtt, GRANULE_STATE_RTT);
	// INFO("LOCKED RTT\n");

	s2tt_walk_lock_unlock(s2_ctx, ipa_addr, S2TT_PAGE_LEVEL, &wi);
	// INFO("WALKED TO LLT\n");
	
	if (wi.last_level != S2TT_PAGE_LEVEL) {
        granule_unlock(wi.g_llt);
		buffer_unmap(rd);
		granule_unlock(g_rd);
        return RMI_ERROR_INPUT;
    }

	s2tt = buffer_granule_map(wi.g_llt, SLOT_RTT);
    assert(s2tt != NULL);
	// INFO("MAPPED LLT\n");

    s2tte = s2tte_read(&s2tt[wi.index]);

	unsigned int attrs = 10000; //placeholder, no-op
	unsigned long pd_addr = rd->pd;
	int target_acl = find_prot_for_mem_with_gpa_in_config(ipa_addr, rd_addr, pd_addr, used_any);
    
	if(target_acl > 0){
		attrs = (unsigned int)target_acl;
	} else {
		INFO("WARNING: TYPE or TARGET_ACL, stopping\n"); //add failure logic later
		attrs = 0; //RW
        return RMI_ERROR_INPUT;
	}
	INFO("Mapping Data Granule at ipa 0x%lx as SHARED with ACL %d in RD 0x%lx\n",
	     ipa_addr, target_acl, rd_addr);
	// pol_pretty_print();
	//replace with s2tte_create_assigned_ram_with_attrs
	s2tte = s2tte_create_assigned_ram_with_attrs(s2_ctx, pa_addr, S2TT_PAGE_LEVEL, attrs);
	// INFO("CREATED S2TTE\n");
	s2tte_write(&s2tt[wi.index], s2tte);
	// INFO("WROTE S2TTE\n");
	/* Invalidate TLB for that IPA */
	s2tt_invalidate_page(s2_ctx, ipa_addr);
	// INFO("INVALIDATED TLB\n");

    buffer_unmap(s2tt);
    granule_unlock(wi.g_llt);
	// INFO("UNLOCKED LLT\n");

	buffer_unmap(rd);
	granule_unlock(g_rd);
    return ret;
}

static unsigned long get_pd_addr_with_hash(uint32_t hash)
{

    INFO("get_pd_addr_with_hash: hash=0x%x\n",
        hash);

    unsigned long rd_addr = get_rd_addr_from_type(hash);

    struct granule *g_rd = find_lock_granule(rd_addr, GRANULE_STATE_RD);
    if (g_rd == NULL) {
        INFO("get_pd_addr_with_hash: failed to lock RD granule for hash=0x%x\n",
                hash);
        return 0;
    }

    struct rd *rd = buffer_granule_map(g_rd, SLOT_RD2);
    if (rd == NULL) {
        INFO("get_pd_addr_with_hash: buffer_granule_map(SLOT_RD2) failed, state=%u\n",
                (unsigned int)granule_get_state(g_rd));
        granule_unlock(g_rd);
        return 0;
    }

    unsigned long pd_addr = rd->pd;
    INFO("get_pd_addr_with_hash: RD->pd = 0x%lx\n",
            pd_addr);
    buffer_unmap(rd);
    granule_unlock(g_rd);

    INFO("get_pd_addr_with_hash: input RD->pd = 0x%lx\n",
         pd_addr);

    return pd_addr;
}

bool load_cfg(unsigned long pd_addr, struct parsed_payload *cfg0)
{
    // INFO("load_cfg: input RD->pd = 0x%lx\n",
        //  pd_addr);

    // INFO("load_cfg: locking PD granule at 0x%lx for reference cfg\n",
    //      pd_addr);
    struct granule *gr = find_lock_granule(pd_addr, GRANULE_STATE_DELEGATED);
    if (!gr) {
        INFO("load_cfg: failed to lock PD granule for reference cfg\n");
        return false;
    }

    uint8_t *pd_phys = buffer_granule_map(gr, SLOT_DELEGATED);
    if (!pd_phys) {
        // INFO("load_cfg: buffer_granule_map(SLOT_DELEGATED) failed for reference cfg\n");
        granule_unlock(gr);
        return false;
    }

    // INFO("load_cfg: copying reference cfg from PD\n");
    memcpy(cfg0, pd_phys, sizeof(*cfg0));

    buffer_unmap(pd_phys);
    granule_unlock(gr);
    // INFO("load_cfg: finished loading reference cfg\n");

    if (config_is_nonempty(cfg0) == false) {
        // INFO("load_cfg: Config is empty!!\n");
        return false;
    }

    return true;
}

static bool load_cfg_with_hash(uint32_t hash, struct parsed_payload *cfg0)
{

    INFO("load_cfg_with_hash: hash=0x%x\n",
        hash);

    // unsigned long rd_addr = get_rd_addr_from_type(hash);
    unsigned long pd_addr = get_pd_addr_with_hash(hash);
    INFO("load_cfg_with_hash: got PD addr=0x%lx for hash=0x%x\n",
         pd_addr, hash);
    if(pd_addr == 0){
        INFO("load_cfg_with_hash: failed to get PD addr from RD for hash=0x%x\n",
                hash);
        return false;
    }
    return load_cfg(pd_addr, cfg0);
}

static bool update_cfg(unsigned long pd_addr, struct parsed_payload *in_cfg)
{
    INFO("update_cfg: input RD->pd = 0x%lx\n",
         pd_addr);

    INFO("update_cfg: locking PD granule at 0x%lx\n",
         pd_addr);
    struct granule *gr = find_lock_granule(pd_addr, GRANULE_STATE_DELEGATED);
    if (!gr) {
        INFO("update_cfg: failed to lock PD granule\n");
        return false;
    }

    uint8_t *pd_phys = buffer_granule_map(gr, SLOT_DELEGATED);
    if (!pd_phys) {
        INFO("update_cfg: buffer_granule_map(SLOT_DELEGATED) failed\n");
        granule_unlock(gr);
        return false;
    }

    INFO("update_cfg: updating cfg into PD\n");
    memcpy(pd_phys, in_cfg, sizeof(*in_cfg));

    buffer_unmap(pd_phys);
    granule_unlock(gr);
    INFO("update_cfg: finished loading new cfg\n");

    return true;
}

static bool measure_cfg(unsigned long rd_addr, struct parsed_payload *in_cfg)
{
    INFO("measure_cfg: input RD->pd = 0x%lx\n",
         rd_addr);

    INFO("measure_cfg: locking PD granule at 0x%lx\n",
         rd_addr);
    struct granule *g_rd = find_lock_granule(rd_addr, GRANULE_STATE_RD);
    if (g_rd == NULL) {
        INFO("measure_cfg: failed to lock RD granule for rd_addr=0x%lx\n",
                rd_addr);
        return 0;
    }

    struct rd *rd = buffer_granule_map(g_rd, SLOT_RD2);
    if (rd == NULL) {
        INFO("measure_cfg: buffer_granule_map(SLOT_RD2) failed, state=%u\n",
                (unsigned int)granule_get_state(g_rd));
        granule_unlock(g_rd);
        return 0;
    }

    unsigned char *current_measurement = rd->measurement[PD_MEASUREMENT_SLOT];

    measurement_hash_compute(rd->algorithm,
            &in_cfg,
            sizeof(in_cfg),
            current_measurement);

    INFO("measure_cfg: updated measurement\n");


    buffer_unmap(rd);
    granule_unlock(g_rd);

    return true;
}

static bool update_and_measure_cfg(unsigned long rd_addr, unsigned long pd_addr, struct parsed_payload *in_cfg)
{
    update_cfg(pd_addr, in_cfg);
    measure_cfg(rd_addr, in_cfg);

    return true;
}

static int load_vm_cfgs_for_gpa(unsigned long gpa,
                                unsigned long in_rd_addr,
                                struct parsed_payload cfgs[PARSER_MAX_VMS],
                                uint32_t hashes[PARSER_MAX_VMS])
{
    int nh = 0;

    /* ===== find VM hashes involved at GPA ===== */
    // INFO("load_vm_cfgs_for_gpa: calling get_vm_hashes_for_gpa(gpa=0x%lx)\n",
        //  gpa);
    // nh = get_vm_hashes_for_gpa(&cfgs[0], gpa, hashes, PARSER_MAX_VMS);
    nh = get_vm_hashes_for_gpa_selfmem(&cfgs[0], gpa, hashes, PARSER_MAX_VMS);
    // INFO("load_vm_cfgs_for_gpa: get_vm_hashes_for_gpa returned nh=%d\n", nh);
    if (nh <= 0) {
        // INFO("load_vm_cfgs_for_gpa: no VM hashes for GPA, returning 0\n");
        return 0;
    }

    int j = 1; // first cfg filled

    /* ===== load each involved VM's cfg and store it ===== */
    for (int i = 0; i < nh; i++) {
        uint32_t hash = hashes[i];
        uint64_t rd_addr = get_rd_addr_from_type(hash);

        if (rd_addr != 0 && rd_addr != in_rd_addr) {
            // INFO("load_vm_cfgs_for_gpa: [%d/%d] hash=0x%x rd_addr=0x%lx\n",
            //      j, nh, hash, rd_addr);

            struct granule *g_rd = find_lock_granule(rd_addr, GRANULE_STATE_RD);
            if (g_rd == NULL) {
                // INFO("load_vm_cfgs_for_gpa: [%d] failed to lock RD granule for hash=0x%x\n",
                //      j, hash);
                return 0;
            }

            struct rd *rd = buffer_granule_map(g_rd, SLOT_RD2);
            if (rd == NULL) {
                // INFO("load_vm_cfgs_for_gpa: [%d] buffer_granule_map(SLOT_RD2) failed, state=%u\n",
                //      j, (unsigned int)granule_get_state(g_rd));
                granule_unlock(g_rd);
                return 0;
            }

            unsigned long pd_addr = rd->pd;
            // INFO("load_vm_cfgs_for_gpa: [%d] RD->pd = 0x%lx\n",
            //      j, pd_addr);
            buffer_unmap(rd);
            granule_unlock(g_rd);

            // INFO("load_vm_cfgs_for_gpa: [%d] locking PD granule at 0x%lx\n",
            //      j, pd_addr);
            struct granule *gr = find_lock_granule(pd_addr, GRANULE_STATE_DELEGATED);
            if (gr == NULL) {
                // INFO("load_vm_cfgs_for_gpa: [%d] failed to lock PD granule\n", j);
                return 0;
            }

            uint8_t *pd_phys = buffer_granule_map(gr, SLOT_RSI_CALL);
            if (pd_phys == NULL) {
                // INFO("load_vm_cfgs_for_gpa: [%d] buffer_granule_map(SLOT_RSI_CALL) failed\n", j);
                granule_unlock(gr);
                return 0;
            }

            // INFO("load_vm_cfgs_for_gpa: [%d] copying cfg from PD\n", j);
            memcpy(&cfgs[j], pd_phys, sizeof(cfgs[j]));

            buffer_unmap(pd_phys);
            granule_unlock(gr);
            // INFO("load_vm_cfgs_for_gpa: [%d] finished loading cfg\n", j);

            if (config_is_nonempty(&cfgs[j]) == false) {
                // INFO("Config is empty!!\n");
                // return 0;
            } else {
                // INFO("Config loaded successfully.\n");
                j++;
            }         
        }
    }

    return j;
}

static int load_vm_cfgs_for_gpa_and_get_pds(unsigned long gpa,
                                            unsigned long in_rd_addr,
                                            struct parsed_payload cfgs[PARSER_MAX_VMS],
                                            uint32_t hashes[PARSER_MAX_VMS],
                                            unsigned long pd_addrs[PARSER_MAX_VMS])
{
    int nh = 0;
	// pd_addrs[0] = in_rd_addr;

    /* ===== find VM hashes involved at GPA ===== */
    INFO("load_vm_cfgs_for_gpa_and_get_pds: calling get_vm_hashes_for_gpa(gpa=0x%lx)\n",
         gpa);
    // nh = get_vm_hashes_for_gpa(&cfgs[0], gpa, hashes, PARSER_MAX_VMS); //start from here --
    nh = get_vm_hashes_for_gpa_selfmem(&cfgs[0], gpa, hashes, PARSER_MAX_VMS);
    INFO("load_vm_cfgs_for_gpa_and_get_pds: get_vm_hashes_for_gpa returned nh=%d\n", nh);
    if (nh <= 0) {
        INFO("load_vm_cfgs_for_gpa_and_get_pds: no VM hashes for GPA, returning 0\n");
        return 0;
    }

    int j = 1; // first cfg filled

    /* ===== load each involved VM's cfg and store it ===== */
    for (int i = 0; i < nh; i++) {
        uint32_t hash = hashes[i];
        uint64_t rd_addr = get_rd_addr_from_type(hash);

        if (rd_addr!= 0 && rd_addr != in_rd_addr) {
            INFO("load_vm_cfgs_for_gpa_and_get_pds: [%d/%d] hash=0x%x rd_addr=0x%lx\n",
                 j, nh, hash, rd_addr);

            struct granule *g_rd = find_lock_granule(rd_addr, GRANULE_STATE_RD);
            if (g_rd == NULL) {
                INFO("load_vm_cfgs_for_gpa_and_get_pds: [%d] failed to lock RD granule for hash=0x%x\n",
                     j, hash);
                return 0;
            }

            struct rd *rd = buffer_granule_map(g_rd, SLOT_RD2);
            if (rd == NULL) {
                INFO("load_vm_cfgs_for_gpa_and_get_pds: [%d] buffer_granule_map(SLOT_RD2) failed, state=%u\n",
                     j, (unsigned int)granule_get_state(g_rd));
                granule_unlock(g_rd);
                return 0;
            }

            unsigned long pd_addr = rd->pd;
            INFO("load_vm_cfgs_for_gpa_and_get_pds: [%d] RD->pd = 0x%lx\n",
                 j, pd_addr);
            buffer_unmap(rd);
            granule_unlock(g_rd);

            INFO("load_vm_cfgs_for_gpa_and_get_pds: [%d] locking PD granule at 0x%lx\n",
                 j, pd_addr);
            struct granule *gr = find_lock_granule(pd_addr, GRANULE_STATE_DELEGATED);
            if (gr == NULL) {
                INFO("load_vm_cfgs_for_gpa_and_get_pds: [%d] failed to lock PD granule\n", j);
                return 0;
            }

            uint8_t *pd_phys = buffer_granule_map(gr, SLOT_RSI_CALL);
            if (pd_phys == NULL) {
                INFO("load_vm_cfgs_for_gpa_and_get_pds: [%d] buffer_granule_map(SLOT_RSI_CALL) failed\n", j);
                granule_unlock(gr);
                return 0;
            }

            INFO("load_vm_cfgs_for_gpa_and_get_pds: [%d] copying cfg from PD\n", j);
            memcpy(&cfgs[j], pd_phys, sizeof(cfgs[j]));

            buffer_unmap(pd_phys);
            granule_unlock(gr);
            INFO("load_vm_cfgs_for_gpa_and_get_pds: [%d] finished loading cfg\n", j);

            if (config_is_nonempty(&cfgs[j]) == false) {
                INFO("load_vm_cfgs_for_gpa_and_get_pds: Config is empty!!\n");
                // return 0;
            } else {
                INFO("load_vm_cfgs_for_gpa_and_get_pds: Config loaded successfully.\n");
                pd_addrs[j] = pd_addr;
                j++;
            }
        }
    }

    return nh;
}

static int load_vm_cfgs_for_any(unsigned long in_rd_addr,
                                struct parsed_payload cfgs[PARSER_MAX_VMS],
                                uint32_t hashes[PARSER_MAX_VMS],
								unsigned long pd_addrs[PARSER_MAX_VMS])
{
    int nh = 0;
	// pd_addrs[0] = in_rd_addr;

    /* ===== find VM hashes involved at GPA ===== */
    INFO("load_vm_cfgs_for_any: calling trt_get_all_types\n");
    nh = trt_get_all_types(hashes);
    INFO("load_vm_cfgs_for_any: get_vm_hashes_for_gpa returned nh=%d\n", nh);
    if (nh <= 0) {
        INFO("load_vm_cfgs_for_any: no VM hashes for GPA, returning 0\n");
        return 0;
    }

    int j = 1; // first cfg filled

    /* ===== load each involved VM's cfg and store it ===== */
    for (int i = 0; i < nh; i++) {
        uint32_t hash = hashes[i];
        uint64_t rd_addr = get_rd_addr_from_type(hash);

        if (rd_addr != in_rd_addr) {
            INFO("load_vm_cfgs_for_any: [%d/%d] hash=0x%x rd_addr=0x%lx\n",
                 j, nh, hash, rd_addr);

            struct granule *g_rd = find_lock_granule(rd_addr, GRANULE_STATE_RD);
            if (g_rd == NULL) {
                INFO("load_vm_cfgs_for_any: [%d] failed to lock RD granule for hash=0x%x\n",
                     j, hash);
                return 0;
            }

            struct rd *rd = buffer_granule_map(g_rd, SLOT_RD2);
            if (rd == NULL) {
                INFO("load_vm_cfgs_for_any: [%d] buffer_granule_map(SLOT_RD2) failed, state=%u\n",
                     j, (unsigned int)granule_get_state(g_rd));
                granule_unlock(g_rd);
                return 0;
            }

            unsigned long pd_addr = rd->pd;
            INFO("load_vm_cfgs_for_any: [%d] RD->pd = 0x%lx\n",
                 j, pd_addr);
            buffer_unmap(rd);
            granule_unlock(g_rd);

            INFO("load_vm_cfgs_for_any: [%d] locking PD granule at 0x%lx\n",
                 j, pd_addr);
            struct granule *gr = find_lock_granule(pd_addr, GRANULE_STATE_DELEGATED);
            if (gr == NULL) {
                INFO("load_vm_cfgs_for_any: [%d] failed to lock PD granule\n", j);
                return 0;
            }

            uint8_t *pd_phys = buffer_granule_map(gr, SLOT_RSI_CALL);
            if (pd_phys == NULL) {
                INFO("load_vm_cfgs_for_any: [%d] buffer_granule_map(SLOT_RSI_CALL) failed\n", j);
                granule_unlock(gr);
                return 0;
            }

            INFO("load_vm_cfgs_for_any: [%d] copying cfg from PD\n", j);
            memcpy(&cfgs[j], pd_phys, sizeof(cfgs[j]));

            buffer_unmap(pd_phys);
            granule_unlock(gr);
            INFO("load_vm_cfgs_for_any: [%d] finished loading cfg\n", j);

            if (config_is_nonempty(&cfgs[j]) == false) {
                INFO("Config is empty!!\n");
                return 0;
            }
			pd_addrs[j] = pd_addr;
            j++;
        }
    }

    return nh;
}


static bool compare_configs(struct parsed_payload cfgs[PARSER_MAX_VMS],
                            int nh)
{
    /* ===== compare all configs ===== */
    // INFO("compare_configs: comparing %d configs\n", nh);
    // INFO("Reference config:\n");
    // dump_parsed_payload(&cfgs[0]);
    for (int i = 1; i < nh; i++) {
        INFO("Compared config:\n");
        // dump_parsed_payload(&cfgs[i]);
        if (!config_equal_ignoring_self(&cfgs[0], &cfgs[i])) {
            INFO("Config mismatch among VMs\n");
            return false; /* ERROR PATH */
        }
    }

    return true;
}

static uint16_t get_self_prot_for_gpa(unsigned long gpa,
                                      struct parsed_payload *cfg0,
                                      bool *used_any)
{
    INFO("get_self_prot_for_gpa: configs match, calling policy_get_self_or_any_prot(gpa=0x%lx)\n",
         gpa);
    /* All configs are equal → continue with your logic */
    // return policy_get_self_prot(cfg0, gpa);
    return policy_get_self_or_any_prot(cfg0, gpa, used_any);
}


uint16_t find_prot_for_mem_with_gpa_in_config(unsigned long gpa,
                                              unsigned long in_rd_addr,
                                              unsigned long pd_addr,
                                              bool *used_any)
{
    struct parsed_payload cfgs[PARSER_MAX_VMS];
    uint32_t hashes[PARSER_MAX_VMS];
    int nh = 0;

    // INFO("find_prot_for_mem_with_gpa_in_config: enter gpa=0x%lx in_rd_addr=0x%lx pd_addr=0x%lx\n",
    //      gpa, in_rd_addr, pd_addr);

    /* ===== get cfg from in_rd_addr (reference cfg) ===== */
    if (!load_cfg(pd_addr, &cfgs[0])) {
        return 0;
    }

    /* ===== find VM hashes involved at GPA + load their cfgs ===== */
    nh = load_vm_cfgs_for_gpa(gpa, in_rd_addr, cfgs, hashes);
    if (nh <= 0) {
        return 0;
    }

    /* ===== compare all configs ===== */
    if (!compare_configs(cfgs, nh)) {
        return 0; /* ERROR PATH */
    }


   	/* All configs are equal → continue with your logic */
    return get_self_prot_for_gpa(gpa, &cfgs[0], used_any);
}


uint16_t update_mem_sharing_mapped_state(unsigned long gpa,
										 unsigned long in_rd_addr,
										 unsigned long pd_addr,
                                         bool used_any)
{
    struct parsed_payload cfgs[PARSER_MAX_VMS];
    uint32_t hashes[PARSER_MAX_VMS];
	unsigned long pd_addrs[PARSER_MAX_VMS];
    bool updated_cfgs[PARSER_MAX_VMS];
    int nh = 0;

    INFO("update_mem_sharing_mapped_state: enter gpa=0x%lx in_rd_addr=0x%lx pd_addr=0x%lx\n",
         gpa, in_rd_addr, pd_addr);

    /* ===== get cfg from in_rd_addr (reference cfg) ===== */
    if (!load_cfg(pd_addr, &cfgs[0])) {
        return 0;
    }
	pd_addrs[0] = pd_addr;

    /* ===== find VM hashes involved at GPA + load their cfgs ===== */
    if(used_any){
        nh = load_vm_cfgs_for_any(in_rd_addr, cfgs, hashes, pd_addrs);
        INFO("update_mem_sharing_mapped_state: nh for ANY %d\n", nh);     
    } else {
        nh = load_vm_cfgs_for_gpa_and_get_pds(gpa, in_rd_addr, cfgs, hashes, pd_addrs);
    }
    if (nh <= 0) {
        return 0;
    }

    if(!pending_mem_if_none(&cfgs[0], gpa)) {
        INFO("update_mem_sharing_mapped_state: pending_mem_if_none failed for PD 0x%lx..trying to check if all pending\n", pd_addrs[0]);
    } else{
        // if(!update_cfg(pd_addrs[0], &cfgs[0])) {
        //     INFO("update_mem_sharing_mapped_state: update_cfg failed for PD 0x%lx\n", pd_addrs[0]);
        //     return 0;
        // }
        /* self-only update: use in_rd_addr here */
        if (!update_and_measure_cfg(in_rd_addr, pd_addr, &cfgs[0])) {
            INFO("update_mem_sharing_mapped_state: update_and_measure_cfg failed for RD 0x%lx PD 0x%lx\n",
                in_rd_addr, pd_addr);
            return 0;
        }
    }

    INFO("update_mem_sharing_mapped_state: Updated configs, nh=%d\n", nh);
    for (int i = 0; i < nh; i++) {
        if(config_is_nonempty(&cfgs[i])) {
            dump_parsed_payload(&cfgs[i]);
        } else {
            INFO("update_mem_sharing_mapped_state: Config [%d] is EMPTY\n", i);
        }
    }
    // dump_parsed_payload(&cfgs[0]);

   	/* All configs are equal → continue with your logic */
    if(!activate_mem_if_quorum(cfgs, nh, gpa, updated_cfgs)) {
        INFO("update_mem_sharing_mapped_state: activate_mem_if_quorum failed, updating only self config\n");
		return 0;
	} else {
		// INFO("update_mem_sharing_mapped_state: activate_mem_if_quorum succeeded, updating cfgs\n");
		// for (int i = 0; i < nh; i++) {
		// 	if(!update_cfg(pd_addrs[i], &cfgs[i])) {
		// 		INFO("update_mem_sharing_mapped_state: update_cfg failed for PD 0x%lx\n", pd_addrs[i]);
		// 		return 0;
		// 	}
			// dump_parsed_payload(&cfgs[i]);
		// }
		// return 1;
        INFO("update_mem_sharing_mapped_state: activate_mem_if_quorum succeeded, updating cfgs\n");
        for (int i = 0; i < nh; i++) {
            if (!updated_cfgs[i])
                continue; /* this cfg wasn't modified by quorum */

            unsigned long rd_addr;
            if (i == 0) {
                rd_addr = in_rd_addr;
            } else {
                rd_addr = get_rd_addr_from_type(hashes[i]);
            }

            if (!update_and_measure_cfg(rd_addr, pd_addrs[i], &cfgs[i])) {
                INFO("update_mem_sharing_mapped_state: update_and_measure_cfg failed for RD 0x%lx (PD 0x%lx)\n",
                     rd_addr, pd_addrs[i]);
                return 0;
            }

            dump_parsed_payload(&cfgs[i]);
        }
        return 1;
	}
}



static int hash_in_set(const uint32_t *arr, size_t count, uint32_t h)
{
    for (size_t i = 0; i < count; ++i) {
        if (arr[i] == h)
            return 1;
    }
    return 0;
}

/* returns:
 *  1 if h was newly added
 *  0 if h was already present
 * -1 if there was no space to add
 */
static int add_hash(uint32_t *arr, size_t *pcount,
                    size_t max, uint32_t h)
{
    if (hash_in_set(arr, *pcount, h))
        return 0;  // already there

    if (*pcount >= max)
        return -1; // no room

    arr[(*pcount)++] = h;
    return 1;
}


static struct parsed_payload next_cfg;
// static void walk_payload(struct parsed_payload *cfg,
//                          uint32_t *out_hashes,
//                          size_t *pcount,
//                          size_t max_hashes)
// {
//     for (size_t i = 0; i < *pcount; ++i) {
//         uint32_t h = out_hashes[i];
//         INFO("walk_payload: currently have hash 0x%x (%zu/%zu)\n",
//              h, i + 1, *pcount);
//     }
//     if (config_is_nonempty(cfg) == false)
//         return;

//     for (uint16_t i = 0; i < cfg->num_ps; ++i) {
//         const struct parsed_ps *ps = &cfg->ps[i];

//         if (ps->mapped != PM_MAPPED_ACTIVE)
//             continue;

//         for (uint16_t m = 0; m < ps->num_mappings; ++m) {
//             const struct parsed_mapping *map = &ps->mappings[m];

//             if (map->vm_index >= cfg->num_vms)
//                 continue;

//             uint32_t vm_hash = cfg->vms[map->vm_index].hash;

//             int added = add_hash(out_hashes, pcount, max_hashes, vm_hash);
//             if (added < 0)
//                 return; // out of space

//             if (added == 1) {
//                 // first time we see this VM, so traverse its config
//                 // struct parsed_payload next_cfg;
//                 load_cfg_with_hash(vm_hash, &next_cfg);
//                 if (config_is_nonempty(&next_cfg))
//                     walk_payload(&next_cfg, out_hashes, pcount, max_hashes);
//             }
//         }
//     }
// }
static void expand_any_ps_flat(const struct parsed_ps *ps,
                               uint32_t *out_hashes,
                               size_t *pcount,
                               size_t max_hashes)
{
    uint32_t all_hashes[PARSER_MAX_VMS];

    /* Adjust signature if needed */
    int num_types = trt_get_all_types(all_hashes);

    for (int t = 0; t < num_types; ++t) {
        uint32_t h = all_hashes[t];

        /* First: try to add the hash. If it's already there, skip it. */
        size_t prev_count = *pcount;
        int added = add_hash(out_hashes, pcount, max_hashes, h);
        if (added < 0) {
            /* out of space; bail out early */
            return;
        }
        if (added == 0) {
            /* already present -> don't touch it, don't load cfg, move on */
            continue;
        }

        /* added == 1: it's new in the set, now load its cfg */
        struct parsed_payload other_cfg;
        if (!load_cfg_with_hash(h, &other_cfg) ||
            !config_is_nonempty(&other_cfg)) {
            /* can't use it -> roll back the add */
            *pcount = prev_count;
            continue;
        }

        /* Does this config have the same ps name ACTIVE? */
        bool matching_ps_active = false;
        for (uint16_t j = 0; j < other_cfg.num_ps; ++j) {
            const struct parsed_ps *other_ps = &other_cfg.ps[j];

            if (other_ps->mapped != PM_MAPPED_ACTIVE)
                continue;

            if (memcmp(other_ps->name,
                       ps->name,
                       sizeof(ps->name)) == 0) {
                matching_ps_active = true;
                break;
            }
        }

        if (!matching_ps_active) {
            /* Not actually in the same ps "bucket" → roll back the add */
            *pcount = prev_count;
            continue;
        }

        /* else: keep it in out_hashes; we’re done with this h */
    }
}



static void walk_payload(struct parsed_payload *cfg,
                         uint32_t *out_hashes,
                         size_t *pcount,
                         size_t max_hashes)
{
    for (size_t i = 0; i < *pcount; ++i) {
        uint32_t h = out_hashes[i];
        INFO("walk_payload: currently have hash 0x%x (%zu/%zu)\n",
             h, i + 1, *pcount);
    }
    if (config_is_nonempty(cfg) == false)
        return;

    for (uint16_t i = 0; i < cfg->num_ps; ++i) {
        const struct parsed_ps *ps = &cfg->ps[i];

        if (ps->mapped != PM_MAPPED_ACTIVE)
            continue;

        bool ps_has_any = false;  /* NEW: does this ps have VM_IDX_ANY mapping? */

        for (uint16_t m = 0; m < ps->num_mappings; ++m) {
            const struct parsed_mapping *map = &ps->mappings[m];

            /* Allow VM_IDX_ANY; otherwise require vm_index < num_vms */
            if (map->vm_index >= cfg->num_vms &&
                map->vm_index != VM_IDX_ANY)
                continue;

            if (map->vm_index == VM_IDX_ANY) {
                /* Remember that this ps has an ANY mapping */
                ps_has_any = true;
                continue;  /* nothing else to do for ANY itself here */
            }

            /* --- "Check VM1" (and other explicit VMs): original behavior --- */
            uint32_t vm_hash = cfg->vms[map->vm_index].hash;

            int added = add_hash(out_hashes, pcount, max_hashes, vm_hash);
            if (added < 0)
                return; // out of space

            if (added == 1) {
                // first time we see this VM, so traverse its config
                // struct parsed_payload next_cfg;
                load_cfg_with_hash(vm_hash, &next_cfg);
                if (config_is_nonempty(&next_cfg))
                    walk_payload(&next_cfg, out_hashes, pcount, max_hashes);
            }
        }

        /* --- "Then runs a flat search on all other VMs in the same ps" --- */
        if (ps_has_any) {
            expand_any_ps_flat(ps, out_hashes, pcount, max_hashes);
            /* NOTE: no extra recursion here */
        }
    }
}

size_t collect_active_vm_hashes(struct parsed_payload *root,
                                uint32_t *out_hashes,
                                size_t max_hashes)
{
    size_t count = 1;

    if (config_is_nonempty(root) == false || !out_hashes || max_hashes == 0)
        return 0;

    walk_payload(root, out_hashes, &count, max_hashes);

    return count;
}


