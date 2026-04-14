/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 */

#include <buffer.h>
#include <debug.h>
#include <granule.h>
#include <measurement.h>
#include <realm.h>
#include <rsi-handler.h>
#include <smc-rsi.h>
#include <smc.h>
#include <string.h>
#include <utils_def.h>
#include <policy_parser.h>
#include <attest_app.h>
#include <sgt.h>

/* Amount of cfg data we will stream after the token.
 * Here we just expose the PD as raw parsed_payload bytes.
 */
#define GROUP_CFG_SIZE   (sizeof(struct parsed_payload))

#define MAX_EXTENDED_SIZE	(64U)
#define MAX_MEASUREMENT_WORDS	(MAX_MEASUREMENT_SIZE / sizeof(unsigned long))


// static unsigned char g_concat_measurement_rim[MAX_MEASUREMENT_SIZE];
// static unsigned char g_concat_measurement_pd[MAX_MEASUREMENT_SIZE];
// static unsigned char g_concat_rpv_buf[MAX_MEASUREMENT_SIZE];
// static unsigned char g_group_measurement[MEASUREMENT_SLOT_NR][MAX_MEASUREMENT_SIZE];
// static uint32_t g_hashes[PARSER_MAX_VMS];
// static struct parsed_payload root_payload;
/* Large SGT buffer must not live on stack in EL2 handlers. */
static struct sgt g_group_attest_sgt_tbl;

/*
 * Function to continue with the token write operation
 */
static void attest_token_continue_write_state_group(struct rec *rec,
					      struct rsi_result *res)
{
	struct granule *gr;
	uintptr_t realm_att_token;
	unsigned long realm_att_token_ipa = rec->regs[1];
	unsigned long offset = rec->regs[2];
	unsigned long size = rec->regs[3];
	enum s2_walk_status walk_status;
	struct s2_walk_result walk_res = { 0UL };
	size_t attest_token_len, length = 0UL;
	struct rec_attest_data *attest_data = rec->aux_data.attest_data;
	enum attest_token_err_t ret;

	/*
	 * Translate realm granule IPA to PA. If returns with
	 * WALK_SUCCESS then the last level page table (llt),
	 * which holds the realm_att_token_buf mapping, is locked.
	 */
	walk_status = realm_ipa_to_pa(rec, realm_att_token_ipa, &walk_res);

	/* Walk parameter validity was checked by RSI_ATTESTATION_TOKEN_INIT */
	assert(walk_status != WALK_INVALID_PARAMS);

	if (walk_status == WALK_FAIL) {
		if (walk_res.ripas_val == RIPAS_EMPTY) {
			res->smc_res.x[0] = RSI_ERROR_INPUT;
		} else {
			/*
			 * Translation failed, IPA is not mapped.
			 * Return to NS host to fix the issue.
			 */
			res->action = STAGE_2_TRANSLATION_FAULT;
			res->rtt_level = walk_res.rtt_level;
		}
		return;
	}

	/* If size of buffer is 0, then return early. */
	if (size == 0UL) {
		res->smc_res.x[0] = RSI_INCOMPLETE;
		goto out_unlock;
	}

	/* Map realm data granule to RMM address space */
	gr = find_granule(walk_res.pa);
	realm_att_token = (uintptr_t)buffer_granule_map(gr, SLOT_RSI_CALL);
	assert(realm_att_token != 0UL);

	/*
	 * Phase 1: stream the CCA token (existing behaviour).
	 */
	if (attest_data->group_phase == GROUP_PHASE_TOKEN) {

		if (attest_data->rmm_cca_token_copied_len == 0UL) {
			ret = attest_cca_token_create(
					&rec->attest_app_data,
					&attest_token_len);

			if (ret != ATTEST_TOKEN_ERR_SUCCESS) {
				res->smc_res.x[0] = RSI_ERROR_INPUT;
				res->smc_res.x[1] = 0UL;
				goto out_unmap;
			}

			attest_data->rmm_cca_token_len = attest_token_len;
		} else {
			attest_token_len = attest_data->rmm_cca_token_len;
		}

		length = (size < attest_token_len) ? size : attest_token_len;

		/* Copy attestation token */
		struct attest_heap_shared *heap_shared =
			app_get_heap_ptr(&rec->attest_app_data);

		memcpy((void *)(realm_att_token + offset),
		       &heap_shared->cca_attest_token_buf[
				attest_data->rmm_cca_token_copied_len],
		       length);

		attest_token_len -= length;

		if (attest_token_len != 0UL) {
			attest_data->rmm_cca_token_len        = attest_token_len;
			attest_data->rmm_cca_token_copied_len += length;

			res->smc_res.x[0] = RSI_INCOMPLETE;
			res->smc_res.x[1] = length;
			goto out_unmap;
		}

		/*
		 * Token creation is complete:
		 * - move to cfg streaming phase.
		 * This call only delivered the *last* chunk of the token;
		 * cfg will start on the next CONTINUE call.
		 */
		attest_data->rmm_cca_token_len     = 0UL;
		/* NOTE: do NOT reset rmm_realm_token_len here anymore. */
		attest_data->group_phase           = GROUP_PHASE_CFG;
		attest_data->group_cfg_index       = 0U;
		attest_data->group_cfg_copied_len  = 0UL;

		res->smc_res.x[0] = RSI_INCOMPLETE;
		res->smc_res.x[1] = length;
		goto out_unmap;
	}

	/*
	 * Phase 2: stream cfg blobs, one per RD/PD.
	 * Each cfg is GROUP_CFG_SIZE bytes from the PD.
	 */
	if (attest_data->group_phase == GROUP_PHASE_CFG) {

		if (attest_data->group_cfg_index >= attest_data->group_cfg_num) {
			/* No cfgs recorded, or all done. */
			attest_data->group_phase = GROUP_PHASE_DONE;
			res->smc_res.x[0] = RSI_SUCCESS;
			res->smc_res.x[1] = 0UL;
			goto out_unmap;
		}

		/* If we've finished the current cfg, advance to the next. */
		if (attest_data->group_cfg_copied_len >= GROUP_CFG_SIZE) {
			attest_data->group_cfg_index++;
			attest_data->group_cfg_copied_len = 0UL;

			if (attest_data->group_cfg_index >= attest_data->group_cfg_num) {
				attest_data->group_phase = GROUP_PHASE_DONE;
				res->smc_res.x[0] = RSI_SUCCESS;
				res->smc_res.x[1] = 0UL;
				goto out_unmap;
			}
		}

		unsigned int idx = attest_data->group_cfg_index;
		unsigned long pd_addr = attest_data->group_cfg_pd_addrs[idx];

		size_t bytes_left_in_cfg =
			GROUP_CFG_SIZE - attest_data->group_cfg_copied_len;
		length = (size < bytes_left_in_cfg) ? size : bytes_left_in_cfg;

		struct granule *cfg_gr;
		uint8_t *pd_phys;

		cfg_gr = find_lock_granule(pd_addr, GRANULE_STATE_DELEGATED);
		if (cfg_gr == NULL) {
			INFO("group cfg: failed to lock PD granule @0x%lx\n", pd_addr);
			res->smc_res.x[0] = RSI_ERROR_UNKNOWN;
			res->smc_res.x[1] = 0UL;
			goto out_unmap;
		}

		pd_phys = buffer_granule_map(cfg_gr, SLOT_DELEGATED);
		if (pd_phys == NULL) {
			INFO("group cfg: buffer_granule_map(SLOT_DELEGATED) failed\n");
			granule_unlock(cfg_gr);
			res->smc_res.x[0] = RSI_ERROR_UNKNOWN;
			res->smc_res.x[1] = 0UL;
			goto out_unmap;
		}

		/* Copy a slice of this cfg into the Realm buffer. */
		memcpy((void *)(realm_att_token + offset),
		       pd_phys + attest_data->group_cfg_copied_len,
		       length);

		buffer_unmap(pd_phys);
		granule_unlock(cfg_gr);

		attest_data->group_cfg_copied_len += length;
		res->smc_res.x[1] = length;

		if ((attest_data->group_cfg_index == (attest_data->group_cfg_num - 1U)) &&
		    (attest_data->group_cfg_copied_len >= GROUP_CFG_SIZE)) {
			/* Last cfg fully sent. */
			attest_data->group_phase = GROUP_PHASE_DONE;
			res->smc_res.x[0] = RSI_SUCCESS;
		} else {
			res->smc_res.x[0] = RSI_INCOMPLETE;
		}

		goto out_unmap;
	}

	/*
	 * Phase 3: all done.
	 */
	if (attest_data->group_phase == GROUP_PHASE_DONE) {
		res->smc_res.x[0] = RSI_SUCCESS;
		res->smc_res.x[1] = 0UL;
	}

out_unmap:
	/* Unmap realm granule */
	buffer_unmap((void *)realm_att_token);
out_unlock:
	/* Unlock last level page table (walk_res.g_llt) */
	granule_unlock(walk_res.llt);
}



// static void group_extend(enum hash_algo algorithm,
//                          unsigned char *agg,        /* current aggregate hash */
//                          const void *new_data,      /* new measurement/RPV */
//                          size_t new_len)
// {
//     uint8_t buf[2 * MAX_MEASUREMENT_SIZE]; /* big enough scratch */
//     size_t hsz = measurement_get_size(algorithm);
// 	INFO("group_extend: alg=%u hsz=%zu new_len=%zu agg=%p new_data=%p\n",
//          (unsigned int)algorithm, hsz, new_len, agg, new_data);

//     /* buf = agg || new_data */
//     memcpy(buf, agg, hsz);
//     memcpy(buf + hsz, new_data, new_len);

//     /* agg = H(buf) */
//     measurement_hash_compute(algorithm, buf, hsz + new_len, agg);
// 	INFO("group_extend: done, first 4 bytes of agg=%02x %02x %02x %02x\n",
//          agg[0], agg[1], agg[2], agg[3]);
// }

static bool ul_in_list(const unsigned long *arr, unsigned int count, unsigned long v)
{
	for (unsigned int i = 0U; i < count; i++) {
		if (arr[i] == v) {
			return true;
		}
	}

	return false;
}

static void add_unique_pd_addr(struct rec_attest_data *attest_data, unsigned long pd_addr)
{
	if ((attest_data == NULL) || (pd_addr == 0UL)) {
		return;
	}

	if (ul_in_list(attest_data->group_cfg_pd_addrs,
		       attest_data->group_cfg_num,
		       pd_addr)) {
		return;
	}

	if (attest_data->group_cfg_num >= PARSER_MAX_VMS) {
		INFO("group cfg: PD list full, dropping pd=0x%lx\n", pd_addr);
		return;
	}

	attest_data->group_cfg_pd_addrs[attest_data->group_cfg_num++] = pd_addr;
}

/*
 * Build connected RD set using SGT as a bipartite graph:
 *   RD --(entry uses PA)--> PA --(entry uses PA)--> RD
 * starting from self_rd_addr.
 */
static unsigned int discover_connected_rds(const struct sgt *sgt_tbl,
					   unsigned long self_rd_addr,
					   unsigned long out_rds[PARSER_MAX_VMS])
{
	unsigned int n = 0U;
	unsigned int q = 0U;

	if ((sgt_tbl == NULL) || (out_rds == NULL) || (self_rd_addr == 0UL)) {
		return 0U;
	}

	out_rds[n++] = self_rd_addr;

	while (q < n) {
		unsigned long current_rd = out_rds[q++];

		for (size_t i = 0U; i < sgt_tbl->count; i++) {
			if (sgt_tbl->entries[i].rd != current_rd) {
				continue;
			}

			unsigned long shared_pa = sgt_tbl->entries[i].pa;
			for (size_t j = 0U; j < sgt_tbl->count; j++) {
				unsigned long peer_rd;

				if (sgt_tbl->entries[j].pa != shared_pa) {
					continue;
				}

				peer_rd = sgt_tbl->entries[j].rd;
				if ((peer_rd == 0UL) || ul_in_list(out_rds, n, peer_rd)) {
					continue;
				}

				if (n >= PARSER_MAX_VMS) {
					INFO("group cfg: RD set truncated at %u entries\n", n);
					return n;
				}

				out_rds[n++] = peer_rd;
			}
		}
	}

	return n;
}

static void build_group_cfg_pd_list(struct rec_attest_data *attest_data,
				    unsigned long self_rd_addr,
				    unsigned long self_pd_addr,
				    const struct sgt *sgt_tbl)
{
	unsigned long connected_rds[PARSER_MAX_VMS];
	unsigned int num_rds;

	if (attest_data == NULL) {
		return;
	}

	attest_data->group_cfg_num = 0U;
	add_unique_pd_addr(attest_data, self_pd_addr);

	if ((sgt_tbl == NULL) || (sgt_tbl->count == 0U)) {
		return;
	}

	num_rds = discover_connected_rds(sgt_tbl, self_rd_addr, connected_rds);
	for (unsigned int i = 0U; i < num_rds; i++) {
		unsigned long rd_addr = connected_rds[i];
		struct granule *g_rd_peer;
		struct rd *rd_peer;
		unsigned long peer_pd;

		if (rd_addr == self_rd_addr) {
			continue;
		}

		g_rd_peer = find_lock_granule(rd_addr, GRANULE_STATE_RD);
		if (g_rd_peer == NULL) {
			INFO("group cfg: cannot lock peer RD @0x%lx\n", rd_addr);
			continue;
		}

		rd_peer = buffer_granule_map(g_rd_peer, SLOT_RD2);
		if (rd_peer == NULL) {
			INFO("group cfg: cannot map peer RD @0x%lx\n", rd_addr);
			granule_unlock(g_rd_peer);
			continue;
		}

		peer_pd = rd_peer->pd;
		buffer_unmap(rd_peer);
		granule_unlock(g_rd_peer);

		add_unique_pd_addr(attest_data, peer_pd);
	}
}

void handle_rsi_attest_token_init_group(struct rec *rec, struct rsi_result *res)
{
	struct rd *rd;
	struct rec_attest_data *attest_data;
	enum attest_token_err_t ret;
	unsigned long self_pd_addr = 0UL;
	unsigned long self_rd_addr;
	unsigned long connected_rds[PARSER_MAX_VMS];
	unsigned int num_rds;
	unsigned char group_measurement[MEASUREMENT_SLOT_NR][MAX_MEASUREMENT_SIZE];
	unsigned char group_rpv[MAX_MEASUREMENT_SIZE];
	enum hash_algo algo;
	bool have_sgt;

	assert(rec != NULL);


	attest_data = rec->aux_data.attest_data;
	res->action = UPDATE_REC_RETURN_TO_REALM;

	/* Initialize length fields in attestation data */
	attest_data->rmm_realm_token_len = 0;
	attest_data->rmm_cca_token_copied_len = 0;
	attest_data->rmm_cca_token_len = 0;

	/* Initialize group streaming state */
	attest_data->group_phase = GROUP_PHASE_TOKEN;
	attest_data->group_cfg_copied_len = 0;
	attest_data->group_cfg_index = 0;
	attest_data->group_cfg_num = 0;

	/*
	 * Calling RSI_ATTESTATION_TOKEN_INIT any time aborts any ongoing
	 * operation.
	 */
	ret = attest_token_sign_ctx_init(&rec->attest_app_data,
					 granule_addr(rec->g_rec));
	if (ret != ATTEST_TOKEN_ERR_SUCCESS) {
		ERROR("Failed to initialize attestation token context.\n");
		res->smc_res.x[0] = RSI_ERROR_UNKNOWN;
		return;
	}

	/*
	 * rd lock is acquired so that measurement cannot be updated
	 * simultaneously by another rec
	 */
	granule_lock(rec->realm_info.g_rd, GRANULE_STATE_RD);
	rd = buffer_granule_map(rec->realm_info.g_rd, SLOT_RD);
	assert(rd != NULL);
	self_pd_addr = rd->pd;
	algo = rd->algorithm;
	memcpy(group_measurement, rd->measurement, sizeof(group_measurement));
	memset(group_rpv, 0, sizeof(group_rpv));
	memcpy(group_rpv, rd->rpv, RPV_SIZE);

	buffer_unmap(rd);
	granule_unlock(rec->realm_info.g_rd);

	self_rd_addr = granule_addr(rec->realm_info.g_rd);
	have_sgt = sgt_load_into(&g_group_attest_sgt_tbl, NULL);
	if (!have_sgt) {
		sgt_init(&g_group_attest_sgt_tbl);
	}

	build_group_cfg_pd_list(attest_data, self_rd_addr, self_pd_addr,
				&g_group_attest_sgt_tbl);

	/*
	 * Aggregate peer measurements/RPV using rolling extend:
	 * agg = H(agg || peer_chunk)
	 */
	num_rds = discover_connected_rds(&g_group_attest_sgt_tbl,
					 self_rd_addr,
					 connected_rds);
	for (unsigned int i = 0U; i < num_rds; i++) {
		unsigned long rd_addr = connected_rds[i];
		struct granule *g_rd_peer;
		struct rd *rd_peer;

		if (rd_addr == self_rd_addr) {
			continue;
		}

		g_rd_peer = find_lock_granule(rd_addr, GRANULE_STATE_RD);
		if (g_rd_peer == NULL) {
			INFO("group attest: cannot lock peer RD @0x%lx\n", rd_addr);
			continue;
		}

		rd_peer = buffer_granule_map(g_rd_peer, SLOT_RD2);
		if (rd_peer == NULL) {
			INFO("group attest: cannot map peer RD @0x%lx\n", rd_addr);
			granule_unlock(g_rd_peer);
			continue;
		}

		attest_do_extend(&rec->attest_app_data,
				   algo,
				   group_measurement[RIM_MEASUREMENT_SLOT],
				   rd_peer->measurement[RIM_MEASUREMENT_SLOT],
				   MAX_MEASUREMENT_SIZE,
				   group_measurement[RIM_MEASUREMENT_SLOT],
				   MAX_MEASUREMENT_SIZE);

		attest_do_extend(&rec->attest_app_data,
				   algo,
				   group_measurement[PD_MEASUREMENT_SLOT],
				   rd_peer->measurement[PD_MEASUREMENT_SLOT],
				   MAX_MEASUREMENT_SIZE,
				   group_measurement[PD_MEASUREMENT_SLOT],
				   MAX_MEASUREMENT_SIZE);

		attest_do_extend(&rec->attest_app_data,
				   algo,
				   group_rpv,
				   rd_peer->rpv,
				   RPV_SIZE,
				   group_rpv,
				   MAX_MEASUREMENT_SIZE);

		buffer_unmap(rd_peer);
		granule_unlock(g_rd_peer);
	}

	ret = attest_realm_token_create(&rec->attest_app_data,
					algo,
					group_measurement,
					group_rpv,
					(const void *)&rec->regs[1]);

	if (ret != ATTEST_TOKEN_ERR_SUCCESS) {
		ERROR("Realm token creation failed.\n");
		res->smc_res.x[0] = RSI_ERROR_UNKNOWN;
		return;
	}

	res->smc_res.x[0] = RSI_SUCCESS;

	/* x1: total max size (token buffer + all cfg blobs) */
	res->smc_res.x[1] = ATTEST_TOKEN_BUF_SIZE +
		attest_data->group_cfg_num * GROUP_CFG_SIZE;

	/* x2: how many cfg blobs will be streamed after the token */
	res->smc_res.x[2] = attest_data->group_cfg_num;

	/* x3: size of each cfg blob, in bytes (currently sizeof(struct parsed_payload)) */
	res->smc_res.x[3] = GROUP_CFG_SIZE;

	INFO("handle_rsi_attest_token_init_group: EXIT success "
		"(total=%lu, cfg_num=%u, cfg_size=%zu)\n",
		res->smc_res.x[1],
		attest_data->group_cfg_num,
		(size_t)GROUP_CFG_SIZE);
}

/*
 * Return 'false' if no IRQ is pending,
 * return 'true' if there is an IRQ pending, and need to return to Host.
 */
static bool check_pending_irq(void)
{
	return (read_isr_el1() != 0UL);
}

static __unused int write_response_to_rec(struct rec *curr_rec,
				uintptr_t resp_granule)
{
	struct granule *rec_granule = NULL;
	struct rec *rec = NULL;
	struct app_data_cfg *attest_app_data;
	bool unmap_unlock_needed = false;
	int ret = 0;

	/*
	 * Check if the granule is the same as the current REC. If it is, the current
	 * code path is guaranteed to have a reference on the REC and the REC
	 * cannot be deleted. It also means that the REC is mapped at the usual
	 * SLOT_REC, so we can avoid locking and mapping the REC and the AUX
	 * granules.
	 */
	if (resp_granule != granule_addr(curr_rec->g_rec)) {

		rec_granule = find_lock_granule(
				resp_granule, GRANULE_STATE_REC);
		if (rec_granule == NULL) {
			/*
			 * REC must have been destroyed, drop the response.
			 */
			VERBOSE("REC granule %lx not found\n", resp_granule);
			return 0;
		}

		rec = buffer_granule_map(rec_granule, SLOT_EL3_TOKEN_SIGN_REC);
		assert(rec != NULL);

		unmap_unlock_needed = true;
	} else {
		rec = curr_rec;
	}
	attest_app_data = &(rec->attest_app_data);

	if (attest_el3_token_write_response_to_ctx(attest_app_data, resp_granule) != 0) {
		ret = -EPERM;
	}

	if (unmap_unlock_needed) {
		buffer_unmap(rec);
		granule_unlock(rec_granule);
	}

	return ret;
}

void handle_rsi_attest_token_continue_group(struct rec *rec,
				      struct rmi_rec_exit *rec_exit,
				      struct rsi_result *res)
{
	struct rec_attest_data *attest_data;
	unsigned long realm_buf_ipa, offset, size;

	assert(rec != NULL);
	assert(rec_exit != NULL);

	attest_data = rec->aux_data.attest_data;
	res->action = UPDATE_REC_RETURN_TO_REALM;

	realm_buf_ipa = rec->regs[1];
	offset = rec->regs[2];
	size = rec->regs[3];

	if (!GRANULE_ALIGNED(realm_buf_ipa) ||
	    (offset >= GRANULE_SIZE) ||
	   ((offset + size) > GRANULE_SIZE) ||
	   ((offset + size) < offset)) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		return;
	}

	if (!addr_in_rec_par(rec, realm_buf_ipa)) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		return;
	}

	/*
	 * Sign the token only while we are in the TOKEN phase.
	 * Once we switch to CFG/DONE, we must not call attest_realm_token_sign()
	 * again, or it will report INVALID_STATE.
	 */
	if (attest_data->group_phase == GROUP_PHASE_TOKEN) {
		while (attest_data->rmm_realm_token_len == 0U) {
			enum attest_token_err_t ret;

			ret = attest_realm_token_sign(&rec->attest_app_data,
						&(attest_data->rmm_realm_token_len));

			if (ret == ATTEST_TOKEN_ERR_INVALID_STATE) {
				/*
				 * Before this call the initial attestation token call
				 * (SMC_RSI_ATTEST_TOKEN_INIT) must have been executed
				 * successfully.
				 */
				res->smc_res.x[0] = RSI_ERROR_STATE;
				return;
			} else if ((ret != ATTEST_TOKEN_ERR_COSE_SIGN_IN_PROGRESS) &&
				   (ret != ATTEST_TOKEN_ERR_SUCCESS)) {
				/* Accessible only in case of failure during token signing */
				ERROR("Realm token signing failed.\n");
				res->smc_res.x[0] = RSI_ERROR_UNKNOWN;
				return;
			}

			res->smc_res.x[0] = RSI_INCOMPLETE;

			/*
			 * Return to RSI handler function after each iteration
			 * to check is there anything else to do (pending IRQ)
			 * or next signing iteration can be executed.
			 */
			if (check_pending_irq()) {
				res->action = UPDATE_REC_EXIT_TO_HOST;
				rec_exit->exit_reason = RMI_EXIT_IRQ;
				return;
			}

#if ATTEST_EL3_TOKEN_SIGN
			/*
			 * Pull response from EL3, find the corresponding rec granule
			 * and attestation context, and have the attestation library
			 * write the response to the context.
			 */
			uintptr_t granule = 0UL;
			int el3_token_sign_ret;

			el3_token_sign_ret =
				attest_el3_token_sign_pull_response_from_el3(&granule);
			if (el3_token_sign_ret == -EAGAIN) {
				continue;
			}

			if (el3_token_sign_ret != 0) {
				ERROR("Failed to pull response from EL3: %d\n",
				      el3_token_sign_ret);
				res->smc_res.x[0] = RSI_ERROR_UNKNOWN;
				return;
			}

			el3_token_sign_ret = write_response_to_rec(rec, granule);
			if (el3_token_sign_ret != 0) {
				ERROR("Failed to write response to REC: %d\n",
				      el3_token_sign_ret);
				res->smc_res.x[0] = RSI_ERROR_UNKNOWN;
				return;
			}
#endif
			/*
			 * If there are no interrupts pending, then continue to pull
			 * requests from EL3 until this RECs request is done.
			 */
		}
	}

	/* Now stream either token (if still in TOKEN phase) or cfgs (CFG phase). */
	attest_token_continue_write_state_group(rec, res);
}
