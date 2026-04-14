#include <assert.h>
#include <buffer.h>
#include <errno.h>
#include <granule.h>
#include <measurement.h>
#include <realm.h>
#include <ripas.h>
#include <s2tt.h>
#include <smc-handler.h>
#include <smc-rmi.h>
#include <smc.h>
#include <status.h>
#include <stddef.h>
#include <string.h>
#include <private_shared_table.h>
// #include <type_rim_rd.h>
#include <rmi_rsi_count.h>
#include <psr_hpa_share_table.h>
#include <sgt_granules.h>
#include <debug.h>
#include <sgt.h>

#ifndef GRANULE_STATE_DATA_SHARED
#define GRANULE_STATE_DATA_SHARED GRANULE_STATE_DATA
#endif

#ifndef s2tte_create_assigned_ram_with_attrs
#define s2tte_create_assigned_ram_with_attrs(_ctx, _pa, _lvl, _attrs) \
	s2tte_create_assigned_ram((_ctx), (_pa), (_lvl))
#endif

//redefining
#define S2AP_RO               1u  // 0b10

static bool validate_map_addr(unsigned long map_addr, //duplicating local helper for debug
			      long level,
			      struct rd *rd)
{
	return ((map_addr < realm_ipa_size(rd)) &&
		s2tte_is_addr_lvl_aligned(&(rd->s2_ctx), map_addr, level));
}

static unsigned long validate_data_create_unknown_shared(unsigned long map_addr,
						  struct rd *rd)
{
	//check if the address is in shared..other RMI later

	if (!validate_map_addr(map_addr, S2TT_PAGE_LEVEL, rd)) {
		return RMI_ERROR_INPUT;
	}

	return RMI_SUCCESS;
}

static unsigned long data_create_unknown_shared(unsigned long rd_addr,
				 unsigned long data_addr,
				 unsigned long map_addr)
{
	struct granule *g_data;
	struct granule *g_rd;
	struct rd *rd;
	struct s2tt_walk wi;
	struct s2tt_context *s2_ctx;
	unsigned long s2tte, *s2tt;
	unsigned char new_data_state = GRANULE_STATE_DELEGATED;
	bool data_was_delegated = true;
	unsigned long ret;

	g_data = find_lock_granule(data_addr, GRANULE_STATE_DELEGATED);
	if (g_data == NULL) {
		g_data = find_lock_granule(data_addr, GRANULE_STATE_DATA_SHARED);
		if(g_data == NULL){
			return RMI_ERROR_INPUT;
		}
		data_was_delegated = false;
		new_data_state = GRANULE_STATE_DATA_SHARED;
	}

	g_rd = find_lock_granule(rd_addr, GRANULE_STATE_RD);
	if (g_rd == NULL) {
		granule_unlock(g_data);
		return RMI_ERROR_INPUT;
	}

	// if (!find_lock_two_granules(data_addr,
	// 			    GRANULE_STATE_DELEGATED,
	// 			    &g_data,
	// 			    rd_addr,
	// 			    GRANULE_STATE_RD,
	// 			    &g_rd)) {
	// 	return RMI_ERROR_INPUT;
	// }

	rd = buffer_granule_map(g_rd, SLOT_RD);
	assert(rd != NULL);

	ret = validate_data_create_unknown_shared(map_addr, rd);
	

	if (ret != RMI_SUCCESS) {
		goto out_unmap_rd;
	}

	s2_ctx = &(rd->s2_ctx);

	/*
	 * If LPA2 is disabled for the realm, then `data_addr` must not be
	 * more than 48 bits wide.
	 */
	if (!s2_ctx->enable_lpa2) {
		if ((data_addr >= (UL(1) << S2TT_MAX_PA_BITS))) {
			ret = RMI_ERROR_INPUT;
			goto out_unmap_rd;
		}
	}

	granule_lock(s2_ctx->g_rtt, GRANULE_STATE_RTT);

	s2tt_walk_lock_unlock(s2_ctx, map_addr, S2TT_PAGE_LEVEL, &wi);
	if (wi.last_level != S2TT_PAGE_LEVEL) {
		ret = pack_return_code(RMI_ERROR_RTT,
					(unsigned char)wi.last_level);
		goto out_unlock_ll_table;
	}

	s2tt = buffer_granule_map(wi.g_llt, SLOT_RTT);
	assert(s2tt != NULL);

	s2tte = s2tte_read(&s2tt[wi.index]);
	if (!s2tte_is_unassigned(s2_ctx, s2tte)) {
		ret = pack_return_code(RMI_ERROR_RTT,
					(unsigned char)S2TT_PAGE_LEVEL);
		goto out_unmap_ll_table;
	}

	/*
	 * Prefault mode: before policy upload/activation, map all requested IPAs
	 * to a single dummy page (RO) to avoid stalling guest accesses when the
	 * final ACLs are not installed yet.
	 *
	 * The dummy page must be provided by the host via SMC_RMI_REALM_DUMMY_PAGE.
	 * We still record the real (data_addr, ipa, rd) tuple in the SGT for later
	 * fix-up.
	 */
	unsigned long pa_to_map = data_addr;
	if (!rd->rsi_uploaded_policy) {
		if (rd->dummy_shared_pa == 0UL) {
			INFO("data_create_unknown_shared: dummy page not set for RD=0x%lx\n",
			     rd_addr);
			ret = RMI_ERROR_INPUT;
			goto out_unmap_ll_table;
		}

		/*
		 * Keep the real page delegated for later fix-up, and map the IPA
		 * to the single dummy backing page.
		 */
		pa_to_map = rd->dummy_shared_pa;
		new_data_state = data_was_delegated ? GRANULE_STATE_DELEGATED
						    : GRANULE_STATE_DATA_SHARED;
	}

	/* IPA-to-PA mapping: always RO for the dummy mapping phase. */
	s2tte = s2tte_create_assigned_ram_with_attrs(s2_ctx, pa_to_map,
						    S2TT_PAGE_LEVEL, S2AP_RO);

    s2tte_write(&s2tt[wi.index], s2tte);
    atomic_granule_get(wi.g_llt);

    ret = RMI_SUCCESS;

	// unsigned int attrs = 10000; //placeholder, no-op
	// bool used_any = false;
	// unsigned long pd_addr = rd->pd;

	// struct parsed_payload cfg;
	// load_cfg(pd_addr, &cfg);
	// bool is_fresh = policy_self_ps_is_fresh_for_gpa(&cfg, map_addr);
	// int psr_id = 0;

	// if(is_fresh == true){
	// 	int rc;
	// 	psr_id = get_psr_id_for_ipa_range(&cfg, map_addr);

	// 	if(psr_id == -1){
	// 		INFO("Error: No PSR found for ipa 0x%lx in config\n", map_addr);
	// 		ret = RMI_ERROR_INPUT;
	// 		goto out_unmap_ll_table;
	// 	}

	// 	/* 1) Claim HPA ownership for this PSR (pre-check) */
	// 	rc = psr_hpa_claim(psr_id, data_addr);
	// 	if (rc != 0) {
	// 		INFO("Error: Could not claim HPA ownership for PSR %d\n", psr_id);
	// 		ret = RMI_ERROR_INPUT;
	// 		goto out_unmap_ll_table;
	// 	}
	// }
	
	// int target_acl = find_prot_for_mem_with_gpa_in_config(map_addr, rd_addr, pd_addr, &used_any);
	// if(used_any == true){
	// 	INFO("Target acl for ANY=%d\n", target_acl);
	// }
	// if(target_acl > 0){
	// 	attrs = (unsigned int)target_acl;
	// } else {
	// 	INFO("WARNING: TYPE or TARGET_ACL is 0, mapping to RW\n"); //add failure logic later
	// 	attrs = 0; //RW
	// }
	// if(attrs != 0){
	// 	INFO("Mapping Data Granule at ipa 0x%lx as SHARED with ACL %d in RD 0x%lx\n",
	// 		map_addr, target_acl, rd_addr);
	// 	// pol_pretty_print();
	// 	//replace with s2tte_create_assigned_ram_with_attrs
	// 	s2tte = s2tte_create_assigned_ram_with_attrs(s2_ctx, data_addr,
	// 						S2TT_PAGE_LEVEL, attrs);

	// 	new_data_state = GRANULE_STATE_DATA;

	// 	s2tte_write(&s2tt[wi.index], s2tte);
	// 	atomic_granule_get(wi.g_llt);

	// 	ret = RMI_SUCCESS;

	// 	// if(ret == RMI_SUCCESS){
	// 	//mark the data granule as shared in some way..other RMI later
	// 	// pst_pretty_print();
	// 	pst_add_pa(rd_addr, map_addr, data_addr);
	// 	// pst_pretty_print();
	// 	rd_addr = pst_get_rd_from_pa(data_addr);
	// 	// INFO("Data Granule 0x%lx marked as shared in PST for RD 0x%lx\n", data_addr, rd_addr);
	// } else {
	// 	INFO("Error in config, cannot map Data Granule as SHARED\n");
	// 	if(is_fresh) {
	// 		(void)psr_hpa_release(psr_id, data_addr); //release ownership
	// 	}
	// 	ret = RMI_ERROR_INPUT;
	// }

out_unmap_ll_table:
	buffer_unmap(s2tt);
out_unlock_ll_table:
	granule_unlock(wi.g_llt);
out_unmap_rd:
	buffer_unmap(rd);
	granule_unlock(g_rd);
	granule_unlock_transition(g_data, new_data_state);
	if(!sgt_load_add_store(data_addr, map_addr, rd_addr)){
		INFO("Could not update SGT for tuple {%lu, %lu, %lu}\n", data_addr, map_addr, rd_addr);
	}
	// if(ret == RMI_SUCCESS){
		// INFO("Trying to update mappings for shared data granule at ipa 0x%lx in RD 0x%lx\n",
		// 	map_addr, rd_addr);
		// if(update_mem_sharing_mapped_state(map_addr, rd_addr, pd_addr, used_any) == 0){
			// INFO("Could not update mappings\n");
	// 	}
	// }
	//rrt_pretty_print();
	return ret;
}

unsigned long smc_data_create_unknown_shared(unsigned long rd_addr,
				      unsigned long data_addr,
				      unsigned long map_addr)
{
	return data_create_unknown_shared(rd_addr, data_addr, map_addr);
}
