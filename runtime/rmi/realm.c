/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 */

#include <arch_features.h>
#include <assert.h>
#include <buffer.h>
#include <debug.h>
#include <feature.h>
#include <granule.h>
#include <measurement.h>
#include <realm.h>
#include <s2tt.h>
#include <simd.h>
#include <smc-handler.h>
#include <smc-rmi.h>
#include <smc.h>
#include <stddef.h>
#include <string.h>
#include <vmid.h>
#include <private_shared_table.h>
#include <realm_add_meta.h>
#include <rmi_rsi_count.h>
#include <sgt.h>
#include <sgt_granules.h>
// #include <rd_table.h>

#define RMI_FEATURE_MIN_IPA_SIZE	PARANGE_0000_WIDTH

static void realm_scrub_stale_bookkeeping(void);

unsigned long smc_realm_activate(unsigned long rd_addr)
{
	struct rd *rd;
	struct granule *g_rd;
	unsigned long ret;

	g_rd = find_lock_granule(rd_addr, GRANULE_STATE_RD);
	if (g_rd == NULL) {
		return RMI_ERROR_INPUT;
	}

	rd = buffer_granule_map(g_rd, SLOT_RD);
	assert(rd != NULL);

	if (get_rd_state_locked(rd) == REALM_NEW) {
		set_rd_state(rd, REALM_ACTIVE);
		ret = RMI_SUCCESS;
	} else {
		ret = RMI_ERROR_REALM;
	}

	// trt_add_entry(rd->measurement[RIM_MEASUREMENT_SLOT], rd_addr);
	// trt_pretty_print();
	ram_add_entry_rim(rd->measurement[RIM_MEASUREMENT_SLOT], rd_addr, rd->pd);
	ram_pretty_print();
	buffer_unmap(rd);

	granule_unlock(g_rd);
	rrt_pretty_print();

	return ret;
}

unsigned long smc_realm_custom_print(unsigned long rd_addr)
{
	struct rd *rd;
	struct granule *g_rd;
	unsigned long ret;

	g_rd = find_lock_granule(rd_addr, GRANULE_STATE_RD);
	if (g_rd == NULL) {
		return RMI_ERROR_INPUT;
	}

	rd = buffer_granule_map(g_rd, SLOT_RD);
	assert(rd != NULL);

	ret = RMI_SUCCESS;

	buffer_unmap(rd);

	granule_unlock(g_rd);

	return ret;
}

unsigned long smc_realm_set_protected_shared_range(unsigned long rd_addr, unsigned long ipa,
				     unsigned long size)
{
	struct rd *rd;
	struct granule *g_rd;
	unsigned long ret;

	g_rd = find_lock_granule(rd_addr, GRANULE_STATE_RD);
	if (g_rd == NULL) {
		return RMI_ERROR_INPUT;
	}

	rd = buffer_granule_map(g_rd, SLOT_RD);
	assert(rd != NULL);

	pst_pretty_print();
	pst_add_tuple(rd_addr, ipa, size);
	pst_pretty_print();
	
	INFO("Protected shared range set in RD 0x%lx: IPA 0x%lx, Size 0x%lx\n",
		rd_addr, ipa, size);

	ret = RMI_SUCCESS;

	buffer_unmap(rd);

	granule_unlock(g_rd);

	return ret;
}


static bool get_realm_params(struct rmi_realm_params *realm_params,
				unsigned long realm_params_addr)
{
	bool ns_access_ok;
	struct granule *g_realm_params;

	g_realm_params = find_granule(realm_params_addr);
	if ((g_realm_params == NULL) ||
		(granule_unlocked_state(g_realm_params) != GRANULE_STATE_NS)) {
		return false;
	}

	ns_access_ok = ns_buffer_read(SLOT_NS, g_realm_params, 0U,
				      sizeof(*realm_params), realm_params);

	return ns_access_ok;
}

static bool is_lpa2_requested(struct rmi_realm_params *p)
{
	return (EXTRACT(RMI_REALM_FLAGS_LPA2, p->flags) == RMI_FEATURE_TRUE);
}

/*
 * See the library pseudocode
 * aarch64/translation/vmsa_faults/AArch64.S2InconsistentSL on which this is
 * modeled.
 */
static bool s2_inconsistent_sl(unsigned int ipa_bits, int sl, bool lpa2)
{
	unsigned int levels = (unsigned int)(S2TT_PAGE_LEVEL - sl);
	unsigned int sl_min_ipa_bits, sl_max_ipa_bits;

	sl_min_ipa_bits = (levels * S2TTE_STRIDE) + GRANULE_SHIFT + 1U;

	/*
	 * The stride for level -1 is only four bits, and we cannot have
	 * concatenated tables at this level, so adjust sl_max_ipa_bits
	 * accordingly.
	 */
	if ((sl == S2TT_MIN_STARTING_LEVEL_LPA2) && (lpa2 == true)) {
		sl_max_ipa_bits = sl_min_ipa_bits + (S2TTE_STRIDE_LM1 - 1U);
	} else {
		sl_max_ipa_bits = sl_min_ipa_bits + (S2TTE_STRIDE - 1U);
	}

	/*
	 * The maximum number of concatenated tables is 16,
	 * hence we are adding 4 to the 'sl_max_ipa_bits' for sl > 0 or
	 * sl == 0 when FEAT_LPA2 is enabled.
	 */
	if ((sl > 0) || ((sl == 0) && (lpa2 == true))) {
		sl_max_ipa_bits += 4U;
	}

	return ((ipa_bits < sl_min_ipa_bits) || (ipa_bits > sl_max_ipa_bits));
}

static bool validate_ipa_bits_and_sl(unsigned int ipa_bits, long sl, bool lpa2)
{
	long min_starting_level;
	unsigned int max_ipa_bits;

	max_ipa_bits = (lpa2 == true) ?
				S2TT_MAX_IPA_BITS_LPA2 : S2TT_MAX_IPA_BITS;

	/* cppcheck-suppress misra-c2012-10.6 */
	min_starting_level = (lpa2 == true) ?
				S2TT_MIN_STARTING_LEVEL_LPA2 : S2TT_MIN_STARTING_LEVEL;

	if ((ipa_bits < S2TT_MIN_IPA_BITS) || (ipa_bits > max_ipa_bits)) {
		return false;
	}

	if ((sl < min_starting_level) || (sl > S2TT_PAGE_LEVEL)) {
		return false;
	}

	/*
	 * We assume ARMv8.4-TTST is supported with RME so the only SL
	 * configuration we need to check with 4K granules is SL == 0 following
	 * the library pseudocode aarch64/translation/vmsa_faults/AArch64.S2InvalidSL.
	 *
	 * Note that this only checks invalid SL values against the properties
	 * of the hardware platform, other misconfigurations between IPA size
	 * and SL is checked in s2_inconsistent_sl.
	 */
	if ((sl == 0L) && (arch_feat_get_pa_width() < 44U)) {
		return false;
	}

	return !s2_inconsistent_sl(ipa_bits, (int)sl, lpa2);
}

/*
 * Calculate the number of s2 root translation tables needed given the
 * starting level and the IPA size in bits. This function assumes that
 * the 'sl' and 'ipa_bits' are consistent with each other and 'ipa_bits'
 * is within architectural boundaries.
 */
static unsigned int s2_num_root_rtts(unsigned int ipa_bits, int sl)
{
	unsigned int levels = (unsigned int)(S2TT_PAGE_LEVEL - sl);
	unsigned int sl_ipa_bits;

	/* First calculate how many bits can be resolved without concatenation */
	sl_ipa_bits = (levels * S2TTE_STRIDE) /* Bits resolved by table walk without SL */
		      + GRANULE_SHIFT	      /* Bits directly mapped to OA */
		      + S2TTE_STRIDE;	      /* Bits resolved by single SL */

	/*
	 * If 'sl' were < 0, sl_ipa_bits would already be at least >= than
	 * 'ipa_bits' as the latter is assumed to be within boundary limits.
	 * This will make the check below pass and return 1U as the number of
	 * s2 root tables, which is the only valid value for a start level < 0.
	 */
	if ((sl_ipa_bits >= ipa_bits)) {
		return U(1);
	}

	return (U(1) << (ipa_bits - sl_ipa_bits));
}

/*
 * Initialize the starting level of stage 2 translation tables.
 *
 * The protected half of the IPA space is initialized to
 * unassigned_empty type of s2tte.
 * The unprotected half of the IPA space is initialized to
 * unassigned_ns type of s2tte.
 * The remaining entries are not initialized.
 */
static void init_s2_starting_level(struct rd *rd)
{
	unsigned long current_ipa = 0U;
	struct granule *g_rtt = rd->s2_ctx.g_rtt;
	unsigned int num_root_rtts;
	unsigned int s2ttes_per_s2tt = (unsigned int)(
		(rd->s2_ctx.s2_starting_level == S2TT_MIN_STARTING_LEVEL_LPA2) ?
			S2TTES_PER_S2TT_LM1 : S2TTES_PER_S2TT);
	unsigned int levels = (unsigned int)(S2TT_PAGE_LEVEL -
						rd->s2_ctx.s2_starting_level);
	/*
	 * The size of the IPA space that is covered by one S2TTE at
	 * the starting level.
	 */
	unsigned long sl_entry_map_size =
			(UL(1)) << U(U(levels * S2TTE_STRIDE) + U(GRANULE_SHIFT));

	num_root_rtts = rd->s2_ctx.num_root_rtts;
	for (unsigned int rtt = 0U; rtt < num_root_rtts; rtt++) {
		unsigned long *s2tt = buffer_granule_map(g_rtt, SLOT_RTT);

		assert(s2tt != NULL);

		for (unsigned int rtte = 0U; rtte < s2ttes_per_s2tt; rtte++) {
			if (addr_in_par(rd, current_ipa)) {
				s2tt[rtte] = s2tte_create_unassigned_empty(
								&(rd->s2_ctx));
			} else {
				s2tt[rtte] = s2tte_create_unassigned_ns(
								&(rd->s2_ctx));
			}

			current_ipa += sl_entry_map_size;
			if (current_ipa == realm_ipa_size(rd)) {
				buffer_unmap(s2tt);
				return;
			}

		}
		buffer_unmap(s2tt);
		g_rtt++;
	}

	/*
	 * We have come to the end of starting level s2tts but we haven't
	 * reached the ipa size.
	 */
	assert(false);
}

static bool validate_realm_params(struct rmi_realm_params *p)
{
	unsigned long feat_reg0 = get_feature_register_0();
	unsigned long max_s2sz = EXTRACT(RMI_FEATURE_REGISTER_0_S2SZ, feat_reg0);
	unsigned long max_bps = EXTRACT(RMI_FEATURE_REGISTER_0_NUM_BPS, feat_reg0);
	unsigned long max_wps = EXTRACT(RMI_FEATURE_REGISTER_0_NUM_WPS, feat_reg0);
	unsigned long max_sve_vl = EXTRACT(RMI_FEATURE_REGISTER_0_SVE_VL, feat_reg0);
	unsigned long max_pmu = EXTRACT(RMI_FEATURE_REGISTER_0_PMU_NUM_CTRS, feat_reg0);
	unsigned int expected_rtts;

	INFO("REALM_CREATE params: flags=0x%lx s2sz=%u sve_vl=%u bps=%u wps=%u pmu=%u algo=%u vmid=%u rtt_base=0x%lx sl=%ld rtt_num=%u\n",
	     p->flags, p->s2sz, p->sve_vl, p->num_bps, p->num_wps,
	     p->pmu_num_ctrs, p->algorithm, (unsigned int)p->vmid,
	     p->rtt_base, p->rtt_level_start, p->rtt_num_start);
	INFO("REALM_CREATE feat0=0x%lx limits: s2sz<=%lu bps<=%lu wps<=%lu sve_vl<=%lu pmu<=%lu\n",
	     feat_reg0, max_s2sz, max_bps, max_wps, max_sve_vl, max_pmu);

	/* Validate LPA2 flag */
	if (is_lpa2_requested(p)  &&
	    (EXTRACT(RMI_FEATURE_REGISTER_0_LPA2, feat_reg0) ==
							RMI_FEATURE_FALSE)) {
		INFO("REALM_CREATE reject: LPA2 requested but unsupported\n");
		return false;
	}

	/* Validate S2SZ field */
	if ((p->s2sz < RMI_FEATURE_MIN_IPA_SIZE) ||
	    (p->s2sz > max_s2sz)) {
		INFO("REALM_CREATE reject: bad s2sz=%u (min=%u max=%lu)\n",
		     p->s2sz, RMI_FEATURE_MIN_IPA_SIZE, max_s2sz);
		return false;
	}

	/*
	 * Validate number of breakpoints and watchpoins.
	 * The values 0 are reserved.
	 */
	if ((p->num_bps == 0U) || (p->num_bps >
		max_bps) ||
		(p->num_wps == 0U) || (p->num_wps >
		max_wps)) {
		INFO("REALM_CREATE reject: bad bps/wps bps=%u (max=%lu) wps=%u (max=%lu)\n",
		     p->num_bps, max_bps, p->num_wps, max_wps);
		return false;
	}

	/* Validate RMI_REALM_FLAGS_SVE flag */
	if (EXTRACT(RMI_REALM_FLAGS_SVE, p->flags) == RMI_FEATURE_TRUE) {
		if (EXTRACT(RMI_FEATURE_REGISTER_0_SVE_EN, feat_reg0) ==
						      RMI_FEATURE_FALSE) {
			INFO("REALM_CREATE reject: SVE requested but unsupported\n");
			return false;
		}

		/* Validate SVE_VL value */
		if (p->sve_vl > max_sve_vl) {
			INFO("REALM_CREATE reject: bad sve_vl=%u (max=%lu)\n",
			     p->sve_vl, max_sve_vl);
			return false;
		}
	}

	/*
	 * Skip validation of RMI_REALM_FLAGS_PMU flag
	 * as RMM always assumes that PMUv3p7+ is present.
	 */

	/* Validate number of PMU counters if PMUv3 is enabled */
	if (EXTRACT(RMI_REALM_FLAGS_PMU, p->flags) == RMI_FEATURE_TRUE) {
		if (p->pmu_num_ctrs > max_pmu) {
			INFO("REALM_CREATE reject: bad pmu_num_ctrs=%u (max=%lu)\n",
			     p->pmu_num_ctrs, max_pmu);
			return false;
		}

		/*
		 * Check if number of PMU counters is 0 and
		 * FEAT_HMPN0 is implemented
		 */
		if ((p->pmu_num_ctrs == 0U) && !is_feat_hpmn0_present()) {
			INFO("REALM_CREATE reject: PMU enabled but pmu_num_ctrs=0 and HMPN0 absent\n");
			return false;
		}
	}

	if (!validate_ipa_bits_and_sl(p->s2sz, p->rtt_level_start,
						is_lpa2_requested(p))) {
		INFO("REALM_CREATE reject: invalid s2sz/sl combination s2sz=%u sl=%ld lpa2=%u\n",
		     p->s2sz, p->rtt_level_start, is_lpa2_requested(p));
		return false;
	}

	expected_rtts = s2_num_root_rtts(p->s2sz, (int)p->rtt_level_start);
	if (expected_rtts != p->rtt_num_start) {
		INFO("REALM_CREATE reject: bad rtt_num_start=%u expected=%u\n",
		     p->rtt_num_start, expected_rtts);
		return false;
	}

	/*
	 * TODO: Check the VMSA configuration which is either static for the
	 * RMM or per realm with the supplied parameters and store the
	 * configuration on the RD, and it can potentially be copied into RECs
	 * later.
	 */

	switch (p->algorithm) {
	case RMI_HASH_SHA_256:
	case RMI_HASH_SHA_512:
		break;
	default:
		INFO("REALM_CREATE reject: unsupported algorithm=%u\n", p->algorithm);
		return false;
	}

	/* Check VMID collision and reserve it atomically if available */
	if (!vmid_reserve((unsigned int)p->vmid)) {
		INFO("REALM_CREATE reject: VMID %u is invalid or already reserved\n",
		     (unsigned int)p->vmid);
		return false;
	}

	return true;
}

static void free_sl_rtts(struct granule *g_rtt, unsigned int num_rtts)
{
	for (unsigned int i = 0U; i < num_rtts; i++) {
		struct granule *g = (struct granule *)((uintptr_t)g_rtt +
						(i * sizeof(struct granule)));

		granule_lock(g, GRANULE_STATE_RTT);
		buffer_granule_memzero(g, SLOT_RTT);
		granule_unlock_transition(g, GRANULE_STATE_DELEGATED);
	}
}

static bool find_lock_rd_granules(unsigned long rd_addr,
				  struct granule **p_g_rd,
				  unsigned long rtt_base_addr,
				  unsigned int num_rtts,
				  struct granule **p_g_rtt_base)
{
	struct granule *g_rd = NULL, *g_rtt_base = NULL;
	unsigned int i = 0U;

	if (rd_addr < rtt_base_addr) {
		g_rd = find_lock_granule(rd_addr, GRANULE_STATE_DELEGATED);
		if (g_rd == NULL) {
			goto out_err;
		}
	}

	for (; i < num_rtts; i++) {
		unsigned long rtt_addr = rtt_base_addr + (i * GRANULE_SIZE);
		struct granule *g_rtt;

		g_rtt = find_lock_granule(rtt_addr, GRANULE_STATE_DELEGATED);
		if (g_rtt == NULL) {
			goto out_err;
		}

		if (i == 0U) {
			g_rtt_base = g_rtt;
		}
	}

	if (g_rd == NULL) {
		g_rd = find_lock_granule(rd_addr, GRANULE_STATE_DELEGATED);
		if (g_rd == NULL) {
			goto out_err;
		}
	}

	*p_g_rd = g_rd;
	*p_g_rtt_base = g_rtt_base;

	return true;

out_err:
	while (i != 0U) {
		granule_unlock((struct granule *)((uintptr_t)g_rtt_base +
						(--i * sizeof(struct granule))));
	}

	if (g_rd != NULL) {
		granule_unlock(g_rd);
	}

	return false;
}

unsigned long smc_realm_pd(unsigned long rd_addr, unsigned long pd_addr)
{
	struct granule *g_rd, *g_pd;
	struct rd *rd;

	g_rd = find_lock_granule(rd_addr, GRANULE_STATE_RD);
	if (g_rd == NULL) {
		return RMI_ERROR_INPUT;
	}

	rd = buffer_granule_map(g_rd, SLOT_RD);
	assert(rd != NULL);

	g_pd = find_lock_granule(pd_addr, GRANULE_STATE_DELEGATED);
	if (g_pd == NULL) {
		buffer_unmap(rd);
		granule_unlock(g_rd);
		return RMI_ERROR_INPUT;
	}

	rd->pd = pd_addr;

	granule_unlock(g_pd);
	buffer_unmap(rd);
	granule_unlock(g_rd);

	return RMI_SUCCESS;
}

unsigned long smc_realm_dummy_page(unsigned long rd_addr, unsigned long dummy_pa)
{
	struct granule *g_rd, *g_dummy;
	struct rd *rd;
	void *dummy;

	g_rd = find_lock_granule(rd_addr, GRANULE_STATE_RD);
	if (g_rd == NULL) {
		return RMI_ERROR_INPUT;
	}

	rd = buffer_granule_map(g_rd, SLOT_RD);
	assert(rd != NULL);

	/*
	 * Only allow setting the dummy page before the policy is uploaded.
	 * After upload, mappings/ACLs should be final and this indirection
	 * is not expected to be used.
	 */
	if (rd->rsi_uploaded_policy) {
		buffer_unmap(rd);
		granule_unlock(g_rd);
		return RMI_ERROR_INPUT;
	}

	/* Idempotent: allow repeated calls with the same PA. */
	if ((rd->dummy_shared_pa != 0UL) && (rd->dummy_shared_pa != dummy_pa)) {
		buffer_unmap(rd);
		granule_unlock(g_rd);
		return RMI_ERROR_INPUT;
	}

	g_dummy = find_lock_granule(dummy_pa, GRANULE_STATE_DELEGATED);
	if (g_dummy == NULL) {
		buffer_unmap(rd);
		granule_unlock(g_rd);
		return RMI_ERROR_INPUT;
	}

	/* Zero it in RMM as a safety net (host should also zero). */
	dummy = buffer_granule_map(g_dummy, SLOT_DELEGATED);
	assert(dummy != NULL);
	memset(dummy, 0, GRANULE_SIZE);
	buffer_unmap(dummy);

	rd->dummy_shared_pa = dummy_pa;

	granule_unlock(g_dummy);
	buffer_unmap(rd);
	granule_unlock(g_rd);

	return RMI_SUCCESS;
}

unsigned long smc_sgt(unsigned long sgt_addr)
{
	struct granule *g_sgt;

	g_sgt = find_lock_granule(sgt_addr, GRANULE_STATE_DELEGATED);
	if (g_sgt == NULL) {
		return RMI_ERROR_INPUT;
	}

	sgt_granules_add_pa(sgt_addr);
	sgt_granules_pretty_print();
	granule_unlock(g_sgt);

	return RMI_SUCCESS;
}

unsigned long smc_realm_create(unsigned long rd_addr,
			       unsigned long realm_params_addr)
{
	struct granule *g_rd, *g_rtt_base;
	struct rd *rd;
	struct rmi_realm_params p;

	/* Defensive scrub in case prior destroy failed before cleanup. */
	realm_scrub_stale_bookkeeping();

	if (!get_realm_params(&p, realm_params_addr)) {
		INFO("REALM_CREATE reject: cannot read realm params at 0x%lx\n",
		     realm_params_addr);
		return RMI_ERROR_INPUT;
	}

	/* coverity[uninit_use_in_call:SUPPRESS] */
	if (!validate_realm_params(&p)) {
		INFO("REALM_CREATE reject: validate_realm_params failed\n");
		return RMI_ERROR_INPUT;
	}

	/*
	 * At this point VMID is reserved for the Realm
	 *
	 * Check for aliasing between rd_addr and
	 * starting level RTT address(es)
	 */
	if (addr_is_contained(p.rtt_base,
			      p.rtt_base + (p.rtt_num_start * GRANULE_SIZE),
			      rd_addr)) {

		/* Free reserved VMID before returning */
		vmid_free((unsigned int)p.vmid);
		return RMI_ERROR_INPUT;
	}

	if (!find_lock_rd_granules(rd_addr, &g_rd, p.rtt_base,
				  p.rtt_num_start, &g_rtt_base)) {
		/* Free reserved VMID */
		vmid_free((unsigned int)p.vmid);
		return RMI_ERROR_INPUT;
	}

	rd = buffer_granule_map(g_rd, SLOT_RD);
	assert(rd != NULL);

	set_rd_state(rd, REALM_NEW);
	set_rd_rec_count(rd, 0UL);
	rd->pd = 0UL;
	rd->sealed_mappings = false;
	rd->rsi_uploaded_policy = false;
	rd->dummy_shared_pa = 0UL;
	rd->s2_ctx.g_rtt = find_granule(p.rtt_base);
	rd->s2_ctx.ipa_bits = p.s2sz;
	rd->s2_ctx.s2_starting_level = (int)p.rtt_level_start;
	rd->s2_ctx.num_root_rtts = p.rtt_num_start;
	rd->s2_ctx.enable_lpa2 = is_lpa2_requested(&p);
	(void)memcpy(&rd->rpv[0], &p.rpv[0], RPV_SIZE);

	rd->s2_ctx.vmid = (unsigned int)p.vmid;

	rd->num_rec_aux = MAX_REC_AUX_GRANULES;

	rd->simd_cfg.sve_en = EXTRACT(RMI_REALM_FLAGS_SVE, p.flags) != 0UL;
	if (rd->simd_cfg.sve_en) {
		rd->simd_cfg.sve_vq = (uint32_t)p.sve_vl;
	}

	if (p.algorithm == RMI_HASH_SHA_256) {
		rd->algorithm = HASH_SHA_256;
	} else {
		rd->algorithm = HASH_SHA_512;
	}

	rd->pmu_enabled = EXTRACT(RMI_REALM_FLAGS_PMU, p.flags) != 0UL;
	rd->pmu_num_ctrs = p.pmu_num_ctrs;

	init_s2_starting_level(rd);

	measurement_realm_params_measure(rd->measurement[RIM_MEASUREMENT_SLOT],
					 rd->algorithm,
					 &p);
	buffer_unmap(rd);

	granule_unlock_transition(g_rd, GRANULE_STATE_RD);

	for (unsigned int i = 0U; i < p.rtt_num_start; i++) {
		granule_unlock_transition(
			(struct granule *)((uintptr_t)g_rtt_base +
			(i * sizeof(struct granule))), GRANULE_STATE_RTT);
	}

	// rdtab_add(rd_addr);

	// rdtab_pretty_print();

	return RMI_SUCCESS;
}

static unsigned long total_root_rtt_refcount(struct granule *g_rtt,
					     unsigned int num_rtts)
{
	unsigned long refcount = 0UL;

	for (unsigned int i = 0U; i < num_rtts; i++) {
		struct granule *g = (struct granule *)((uintptr_t)g_rtt +
					(i * sizeof(struct granule)));
	       /*
		* Lock starting from the RTT root.
		* Enforcing locking order RD->RTT is enough to ensure
		* deadlock free locking guarentee.
		*/
		granule_lock(g, GRANULE_STATE_RTT);
		refcount += (unsigned long)granule_refcount_read(g);
		granule_unlock(g);
	}

	return refcount;
}

static size_t sgt_remove_entries_for_rd(struct sgt *t, unsigned long rd_addr)
{
	size_t removed = 0U;
	size_t w = 0U;
	size_t before_count;

	if (t == NULL) {
		return 0U;
	}

	before_count = t->count;

	for (size_t i = 0U; i < t->count; i++) {
		if (t->entries[i].rd == rd_addr) {
			removed++;
			continue;
		}

		if (w != i) {
			t->entries[w] = t->entries[i];
		}
		w++;
	}

	t->count = w;
	if (removed > 0U) {
		INFO("SGT remove_by_rd: rd=0x%lx removed=%lu before=%lu after=%lu\n",
		     rd_addr, (unsigned long)removed,
		     (unsigned long)before_count, (unsigned long)t->count);
	}
	return removed;
}

static bool rd_addr_is_live(unsigned long rd_addr)
{
	type_rim_t ram_e;

	return ram_get_entry_from_rd(rd_addr, &ram_e) == 1;
}

static size_t sgt_remove_stale_rd_entries(struct sgt *t)
{
	size_t removed = 0U;
	size_t w = 0U;
	size_t before_count;

	if (t == NULL) {
		return 0U;
	}

	before_count = t->count;

	for (size_t i = 0U; i < t->count; i++) {
		if (!rd_addr_is_live(t->entries[i].rd)) {
			INFO("SGT stale_remove: drop entry rd=0x%lx pa=0x%lx gpa=0x%lx\n",
			     t->entries[i].rd, t->entries[i].pa, t->entries[i].gpa);
			removed++;
			continue;
		}

		if (w != i) {
			t->entries[w] = t->entries[i];
		}
		w++;
	}

	t->count = w;
	if (removed > 0U) {
		INFO("SGT stale_remove: removed=%lu before=%lu after=%lu\n",
		     (unsigned long)removed,
		     (unsigned long)before_count,
		     (unsigned long)t->count);
	}
	return removed;
}

/*
 * struct sgt is large (entries[4096]); keep destroy scratch buffers static to
 * avoid blowing the per-CPU RMM stack during REALM_DESTROY.
 */
static struct sgt g_realm_destroy_sgt_tbl;
static unsigned long g_realm_destroy_sgt_addrs[MAX_SGT_GRANULES_ENTRIES];

static void realm_scrub_stale_bookkeeping(void)
{
	bool have_sgt;
	bool cleared_sgt = false;
	size_t sgt_removed = 0U;
	unsigned int pst_removed;
	unsigned int ram_removed;

	pst_removed = pst_scrub_stale_entries();
	ram_removed = ram_scrub_stale_entries();

	memset(g_realm_destroy_sgt_addrs, 0, sizeof(g_realm_destroy_sgt_addrs));
	have_sgt = sgt_load_into(&g_realm_destroy_sgt_tbl,
				 g_realm_destroy_sgt_addrs);
	if (!have_sgt) {
		INFO("SGT scrub: load failed; preserving granule registry\n");
	} else {
		sgt_removed = sgt_remove_stale_rd_entries(&g_realm_destroy_sgt_tbl);
		if (sgt_removed > 0U) {
			if (g_realm_destroy_sgt_tbl.count == 0U) {
				INFO("SGT scrub: table empty after stale removal, clearing granules\n");
				cleared_sgt = sgt_clear_granules(g_realm_destroy_sgt_addrs);
				if (!cleared_sgt) {
					INFO("SGT scrub: clear failed; preserving granule registry\n");
				}
			} else {
				INFO("SGT scrub: storing table after stale removal, count=%lu\n",
				     (unsigned long)g_realm_destroy_sgt_tbl.count);
				(void)sgt_store_to_granules(g_realm_destroy_sgt_addrs,
							    &g_realm_destroy_sgt_tbl);
			}
		}
	}
	if (cleared_sgt && sgt_granules_all_released_to_host()) {
		unsigned int pruned = sgt_granules_prune_released_to_host();
		INFO("SGT scrub: pruned released granules=%u\n", pruned);
	} else if (cleared_sgt) {
		unsigned int pruned = sgt_granules_prune_released_to_host();
		INFO("SGT scrub: table cleared; pruned released granules=%u\n", pruned);
	}

	if ((pst_removed > 0U) || (ram_removed > 0U) || (sgt_removed > 0U)) {
		INFO("realm_create scrub: pst_removed=%u ram_removed=%u sgt_removed=%lu\n",
		     pst_removed, ram_removed, (unsigned long)sgt_removed);
	}
}

static void realm_cleanup_sgt_for_rd(unsigned long rd_addr)
{
	bool have_sgt;
	bool cleared_sgt = false;
	size_t removed;

	memset(g_realm_destroy_sgt_addrs, 0, sizeof(g_realm_destroy_sgt_addrs));

	have_sgt = sgt_load_into(&g_realm_destroy_sgt_tbl,
				 g_realm_destroy_sgt_addrs);
	if (!have_sgt) {
		INFO("SGT cleanup: load failed while cleaning rd=0x%lx\n", rd_addr);
		INFO("SGT cleanup: preserving granule registry on load failure\n");
		return;
	}

	removed = sgt_remove_entries_for_rd(&g_realm_destroy_sgt_tbl, rd_addr);

	if (removed > 0U) {
		if (g_realm_destroy_sgt_tbl.count == 0U) {
			INFO("SGT cleanup: rd=0x%lx removed all entries, clearing granules\n",
			     rd_addr);
			cleared_sgt = sgt_clear_granules(g_realm_destroy_sgt_addrs);
			if (!cleared_sgt) {
				INFO("SGT cleanup: clear failed for rd=0x%lx; preserving granule registry\n",
				     rd_addr);
			}
		} else {
			INFO("SGT cleanup: rd=0x%lx storing table after removal, count=%lu\n",
			     rd_addr, (unsigned long)g_realm_destroy_sgt_tbl.count);
			(void)sgt_store_to_granules(g_realm_destroy_sgt_addrs,
						    &g_realm_destroy_sgt_tbl);
		}
	} else {
		INFO("SGT cleanup: rd=0x%lx no entries removed\n", rd_addr);
	}
	if (cleared_sgt && sgt_granules_all_released_to_host()) {
		unsigned int pruned = sgt_granules_prune_released_to_host();
		INFO("SGT cleanup: pruned released granules=%u\n", pruned);
	} else if (cleared_sgt) {
		unsigned int pruned = sgt_granules_prune_released_to_host();
		INFO("SGT cleanup: table cleared; pruned released granules=%u\n", pruned);
	}

	/*
	 * SGT backing granules are host-owned and host must undelegate/free.
	 * RMM only resets the PA registry after a successful clear operation.
	 */
}

static void realm_cleanup_meta_for_rd(unsigned long rd_addr,
				      unsigned long pd_addr,
				      bool have_pd_addr)
{
	(void)ram_remove_entry_from_rd(rd_addr);
	if (have_pd_addr) {
		(void)ram_remove_entry_from_pd(pd_addr);
	}
	(void)pst_remove_entries_from_rd(rd_addr);
}

unsigned long smc_realm_destroy(unsigned long rd_addr)
{
	struct granule *g_rd;
	struct granule *g_rtt;
	struct rd *rd;
	unsigned int num_rtts;
	unsigned long pd_addr;
	int res;

	/* RD should not be destroyed if refcount != 0. */
	res = find_lock_unused_granule(rd_addr, GRANULE_STATE_RD, &g_rd);
	if (res != 0) {
		switch (res) {
		case -EINVAL:
			return RMI_ERROR_INPUT;
		default:
			assert(res == -EBUSY);
			/*
			 * Best-effort early cleanup: if destroy fails because RD is
			 * still busy, clear PST/RAM tuples for this RD so stale
			 * metadata does not leak across realm lifecycles.
			 */
			realm_cleanup_meta_for_rd(rd_addr, 0UL, false);
			return RMI_ERROR_REALM;
		}
	}

	rd = buffer_granule_map(g_rd, SLOT_RD);
	assert(rd != NULL);

	g_rtt = rd->s2_ctx.g_rtt;
	num_rtts = rd->s2_ctx.num_root_rtts;
	pd_addr = rd->pd;

	/* Check if granules are unused */
	if (total_root_rtt_refcount(g_rtt, num_rtts) != 0UL) {
		/*
		 * Best-effort early cleanup for failed destroy.
		 */
		realm_cleanup_meta_for_rd(rd_addr, 0UL, false);
		buffer_unmap(rd);
		granule_unlock(g_rd);
		return RMI_ERROR_REALM;
	}

	/*
	 * All the mappings in the Realm have been removed and the TLB caches
	 * are invalidated. Therefore, there are no TLB entries tagged with
	 * this Realm's VMID (in this security state).
	 * Just release the VMID value so it can be used in another Realm.
	 */
	vmid_free(rd->s2_ctx.vmid);

	/*
	 * Cleanup custom metadata owned by this Realm before RD is zeroed.
	 */
	realm_cleanup_meta_for_rd(rd_addr, pd_addr, true);
	realm_cleanup_sgt_for_rd(rd_addr);

	rd->pd = 0UL;
	rd->dummy_shared_pa = 0UL;
	buffer_unmap(rd);

	free_sl_rtts(g_rtt, num_rtts);

	/* This implicitly destroys the measurement */
	buffer_granule_memzero(g_rd, SLOT_RD);
	granule_unlock_transition(g_rd, GRANULE_STATE_DELEGATED);

	return RMI_SUCCESS;
}
