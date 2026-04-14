/* policy_validator_actions.c */
#include <policy_validator_actions.h>

#ifndef s2tte_create_assigned_ram_with_attrs
#define s2tte_create_assigned_ram_with_attrs(_ctx, _pa, _lvl, _attrs) \
	s2tte_create_assigned_ram((_ctx), (_pa), (_lvl))
#endif

static bool s2_ctx_cached = false;
static struct s2tt_context cached_s2_ctx;
static unsigned long cached_start_ipa = 0UL;
#define MAX_KEEP_RANGES (PARSER_MAX_MEMS * PARSER_MAX_MAPS)

void policy_validator_actions_set_s2_ctx(const struct s2tt_context *s2_ctx,
                                         unsigned long start_ipa)
{
	if (s2_ctx == NULL) {
		s2_ctx_cached = false;
		cached_start_ipa = 0UL;
		return;
	}

	cached_s2_ctx = *s2_ctx;
	cached_start_ipa = start_ipa;
	s2_ctx_cached = true;
}

void policy_validator_actions_clear_s2_ctx(void)
{
	s2_ctx_cached = false;
	cached_start_ipa = 0UL;
}

static const struct parsed_mem *find_mem_by_name_ro(const struct parsed_payload *cfg,
                                                    const char name[4])
{
	if (!cfg) {
		INFO("validator: find_mem_by_name_ro: cfg=NULL\n");
		return NULL;
	}

	for (uint16_t i = 0; i < cfg->num_mems && i < PARSER_MAX_MEMS; i++) {
		if (memcmp(cfg->mems[i].name, name, 4) == 0) {
			return &cfg->mems[i];
		}
	}

	return NULL;
}

struct activation_rule {
	uint64_t start_gpa;
	uint64_t end_gpa;
	unsigned int attrs;
	bool is_any;
};

static bool gpa_in_range(uint64_t gpa, uint64_t start, uint64_t end)
{
	return (gpa >= start) && (gpa < end);
}

static int build_self_activation_rules(const struct parsed_payload *self_cfg,
				       const struct parsed_mem *m,
				       struct activation_rule *rules,
				       size_t *out_n_rules)
{
	size_t n = 0;
	uint16_t self_idx;

	if (!self_cfg || !m || !rules || !out_n_rules) {
		return PVAL_EARGS;
	}

	if (self_cfg->self_vm_index >= self_cfg->num_vms) {
		return PVAL_ECFG_MISMATCH;
	}
	self_idx = self_cfg->self_vm_index;

	for (uint16_t i = 0; i < m->num_mappings && i < PARSER_MAX_MAPS; i++) {
		const struct parsed_mapping *mp = &m->mappings[i];

		if (n >= PARSER_MAX_MAPS) {
			return PVAL_ECFG_MISMATCH;
		}

		/*
		 * Activation here is self-only. Keep only:
		 *  - self explicit mapping(s)
		 *  - ANY mapping(s) as fallback for self.
		 */
		if ((mp->vm_index == self_idx) || (mp->vm_index == VM_IDX_ANY)) {
			struct activation_rule *r = &rules[n];
			r->start_gpa = (uint64_t)mp->gpa;
			r->end_gpa = r->start_gpa + (uint64_t)m->size;
			r->attrs = (unsigned int)mp->prot;
			r->is_any = (mp->vm_index == VM_IDX_ANY);
			n++;
		}
	}

	*out_n_rules = n;
	return PVAL_OK;
}

static bool find_target_attrs_for_self_gpa(const struct activation_rule *rules,
					   size_t n_rules,
					   uint64_t gpa,
					   unsigned int *out_attrs)
{
	for (size_t i = 0; i < n_rules; i++) {
		const struct activation_rule *r = &rules[i];

		if (r->is_any) {
			continue;
		}

		if (gpa_in_range(gpa, r->start_gpa, r->end_gpa)) {
			*out_attrs = r->attrs;
			return true;
		}
	}

	for (size_t i = 0; i < n_rules; i++) {
		const struct activation_rule *r = &rules[i];

		if (!r->is_any) {
			continue;
		}

		if (gpa_in_range(gpa, r->start_gpa, r->end_gpa)) {
			*out_attrs = r->attrs;
			return true;
		}
	}

	return false;
}

static int rewrite_one_rd_gpa_mapping(const struct s2tt_context *s2_ctx,
				      uint64_t gpa,
				      unsigned long pa,
				      unsigned int attrs)
{
	struct s2tt_walk wi;
	unsigned long *s2tt;
	unsigned long new_s2tte;

	if (!s2_ctx || !s2_ctx->g_rtt) {
		return PVAL_ECFG_MISMATCH;
	}

	granule_lock(s2_ctx->g_rtt, GRANULE_STATE_RTT);
	s2tt_walk_lock_unlock(s2_ctx, (unsigned long)gpa, S2TT_PAGE_LEVEL, &wi);

	if ((wi.g_llt == NULL) || (wi.last_level != S2TT_PAGE_LEVEL)) {
		if (wi.g_llt != NULL) {
			granule_unlock(wi.g_llt);
		}
		return PVAL_ESGT_COVERAGE;
	}

	s2tt = buffer_granule_map(wi.g_llt, SLOT_RTT);
	if (s2tt == NULL) {
		granule_unlock(wi.g_llt);
		return PVAL_ECFG_MISMATCH;
	}

	new_s2tte = s2tte_create_assigned_ram_with_attrs(s2_ctx, pa,
							  S2TT_PAGE_LEVEL, attrs);
	s2tte_write(&s2tt[wi.index], new_s2tte);
	s2tt_invalidate_page(s2_ctx, (unsigned long)gpa);

	buffer_unmap(s2tt);
	granule_unlock(wi.g_llt);

	return PVAL_OK;
}

static int activate_mem_mappings_from_sgt(struct parsed_payload *self_cfg,
					  const struct sgt *sgt,
					  const char mem_name[4])
{
	const struct parsed_mem *m;
	struct activation_rule rules[PARSER_MAX_MAPS];
	size_t n_rules = 0;
	unsigned long self_rd = 0;
	struct granule *g_self_rd = NULL;
	struct rd *self_rd_obj = NULL;
	const struct s2tt_context *ctx = NULL;

	if (!self_cfg || !sgt || !mem_name) {
		return PVAL_EARGS;
	}

	m = find_mem_by_name_ro(self_cfg, mem_name);
	if (!m) {
		return PVAL_ENOMEM_NOTFOUND;
	}

	if (m->type != MEM_PROTECTED) {
		return PVAL_ENOMEM_NOTFOUND;
	}

	if (build_self_activation_rules(self_cfg, m, rules, &n_rules) != PVAL_OK) {
		return PVAL_ECFG_MISMATCH;
	}

	if (self_cfg->self_vm_index < self_cfg->num_vms) {
		uint32_t self_hash = self_cfg->vms[self_cfg->self_vm_index].hash;
		if (!get_peer_rd(self_hash, &self_rd)) {
			return PVAL_ECFG_MISMATCH;
		}
	} else {
		return PVAL_ECFG_MISMATCH;
	}

	if (s2_ctx_cached) {
		ctx = &cached_s2_ctx;
	} else {
		g_self_rd = find_lock_granule(self_rd, GRANULE_STATE_RD);
		if (g_self_rd == NULL) {
			INFO("validator: activation: failed to lock self RD (rd=0x%lx)\n", self_rd);
			return PVAL_ECFG_MISMATCH;
		}

		self_rd_obj = buffer_granule_map(g_self_rd, SLOT_RD2);
		if (self_rd_obj == NULL) {
			INFO("validator: activation: failed to map self RD (rd=0x%lx)\n", self_rd);
			granule_unlock(g_self_rd);
			return PVAL_ECFG_MISMATCH;
		}
		ctx = &self_rd_obj->s2_ctx;
	}

	for (size_t i = 0; i < sgt->count; i++) {
		const struct sgt_entry *e = &sgt->entries[i];
		unsigned int attrs = 0U;
		int rc;

		/* Self-only activation */
		if (e->rd != self_rd) {
			continue;
		}

		if (!find_target_attrs_for_self_gpa(rules, n_rules,
						    (uint64_t)e->gpa, &attrs)) {
			continue;
		}

		rc = rewrite_one_rd_gpa_mapping(ctx, (uint64_t)e->gpa, e->pa, attrs);
		if (rc != PVAL_OK) {
			INFO("validator: activation: remap failed rd=0x%lx gpa=0x%lx pa=0x%lx rc=%d\n",
			     e->rd, e->gpa, e->pa, rc);
			if (self_rd_obj != NULL) {
				buffer_unmap(self_rd_obj);
				granule_unlock(g_self_rd);
			}
			return rc;
		}
	}

	if (self_rd_obj != NULL) {
		buffer_unmap(self_rd_obj);
		granule_unlock(g_self_rd);
	}

	return PVAL_OK;
}


/*
 * Unmap all ASSIGNED_NS mappings for a Realm, using its s2tt_context,
 * starting from 'start_ipa' (typically the Realm PAR size).
 *
 * Caller must hold the RD lock, so lock ordering is RD -> RTT.
 *
 * For each unmapped entry we log: IPA, PA, last_level.
 */
struct ipa_range {
	uint64_t start;
	uint64_t end;
};

static bool ipa_is_kept(uint64_t ipa,
			const struct ipa_range *keep,
			size_t n_keep)
{
	for (size_t i = 0; i < n_keep; i++) {
		if ((ipa >= keep[i].start) && (ipa < keep[i].end)) {
			return true;
		}
	}
	return false;
}

static void rmm_unmap_unprotected_ns_ctx_except(const struct s2tt_context *s2_ctx,
						unsigned long start_ipa,
						const struct ipa_range *keep,
						size_t n_keep)
{
	struct s2tt_walk wi;
	unsigned long max_ipa;
	unsigned long ipa;
	unsigned long page_size;
	unsigned long scanned_entries = 0UL;
	unsigned long unmapped_entries = 0UL;
	unsigned long kept_entries = 0UL;

	if (s2_ctx->g_rtt == NULL) {
		INFO("unmap_ns: g_rtt is NULL\n");
		return;
	}

	/* Compute maximum IPA based on ipa_bits */
	if (s2_ctx->ipa_bits >= (sizeof(unsigned long) * 8U)) {
		max_ipa = ~0UL;
	} else {
		max_ipa = (1UL << s2_ctx->ipa_bits);
	}

	if (start_ipa >= max_ipa) {
		INFO("unmap_ns: start_ipa (0x%lx) >= max_ipa (0x%lx), nothing to scan\n",
		     start_ipa, max_ipa);
		return;
	}

	/*
	 * We care about 4 KiB page mappings (level 3) because that is what
	 * RMI_RTT_MAP_UNPROTECTED uses in your logs (ulevel == 3).
	 */
	page_size = s2tte_map_size(S2TT_PAGE_LEVEL);

	/* Align starting IPA up to the page size. */
	ipa = (start_ipa + page_size - 1UL) & ~(page_size - 1UL);

	while (ipa < max_ipa) {
		unsigned long *table;
		unsigned long s2tte;
		long level;
		unsigned long next_ipa;

		scanned_entries++;
		if ((scanned_entries & 0xFFFFUL) == 0UL) {
			INFO("unmap_ns: progress: ipa=0x%lx scanned=%lu unmapped=%lu\n",
			     ipa, scanned_entries, unmapped_entries);
		}

		/*
		 * Ask the walker to go all the way down to PAGE_LEVEL (3).
		 * This mirrors what map_unmap_ns() does when level == S2TT_PAGE_LEVEL.
		 */
		granule_lock(s2_ctx->g_rtt, GRANULE_STATE_RTT);
		s2tt_walk_lock_unlock(s2_ctx, ipa, S2TT_PAGE_LEVEL, &wi);
		/* After this: root RTT is unlocked, wi.g_llt is locked. */

		if (wi.g_llt == NULL) {
			INFO("unmap_ns: walk returned NULL g_llt for ipa=0x%lx\n", ipa);
			/* Avoid spinning: bump IPA to next page. */
			ipa += page_size;
			continue;
		}

		table = buffer_granule_map(wi.g_llt, SLOT_RTT);
		if (table == NULL) {
			INFO("unmap_ns: NULL table for IPA=0x%lx (last_level=%ld index=%lu)\n",
			     ipa, wi.last_level, wi.index);
			granule_unlock(wi.g_llt);
			break;
		}

		s2tte = s2tte_read(&table[wi.index]);
		level = wi.last_level;

		/*
		 * Only unmap if we actually reached PAGE_LEVEL (3) and the entry
		 * is ASSIGNED_NS there – this matches how UNMAP_NS validates:
		 *   (wi.last_level == level == S2TT_PAGE_LEVEL) && assigned_ns
		 */
		if ((level == S2TT_PAGE_LEVEL) && s2tte_is_assigned_ns(s2_ctx, s2tte, level)) {
			unsigned long pa = s2tte_pa(s2_ctx, s2tte, level);
			uint64_t gpa = (uint64_t)ipa;

			if (ipa_is_kept(gpa, keep, n_keep)) {
				kept_entries++;
			} else {
				INFO("unmap_ns: UNMAP IPA=0x%lx PA=0x%lx level=%ld\n",
				     ipa, pa, level);

				unsigned long new_s2tte = s2tte_create_unassigned_ns(s2_ctx);
				s2tte_write(&table[wi.index], new_s2tte);

				/* Same invalidation behaviour as map_unmap_ns() for UNMAP_NS. */
				s2tt_invalidate_page(s2_ctx, ipa);

				unmapped_entries++;
			}
		}

		/*
		 * Advance using the existing helper – this is the same helper
		 * used in the UNMAP_NS path in map_unmap_ns().
		 */
		next_ipa = s2tt_skip_non_live_entries(s2_ctx, ipa, table, &wi);

		buffer_unmap(table);
		granule_unlock(wi.g_llt);

		if (next_ipa <= ipa) {
			/* Safety net: avoid infinite loops – move to the next page. */
			ipa += page_size;
		} else {
			ipa = next_ipa;
		}
	}

	INFO("unmap_ns: done: scanned=%lu unmapped=%lu kept=%lu\n",
	     scanned_entries, unmapped_entries, kept_entries);
}

static size_t collect_unprotected_keep_ranges(const struct parsed_payload *self_cfg,
					      struct ipa_range *out_keep,
					      size_t cap)
{
	size_t n = 0;
	uint16_t self_idx = self_cfg->self_vm_index;

	for (uint16_t mi = 0; mi < self_cfg->num_mems && mi < PARSER_MAX_MEMS; mi++) {
		const struct parsed_mem *m = &self_cfg->mems[mi];

		if (m->type != MEM_UNPROTECTED) {
			continue;
		}

		for (uint16_t j = 0; j < m->num_mappings && j < PARSER_MAX_MAPS; j++) {
			const struct parsed_mapping *mp = &m->mappings[j];
			struct ipa_range r;

			if ((mp->vm_index != self_idx) && (mp->vm_index != VM_IDX_ANY)) {
				continue;
			}

			if (n >= cap) {
				return n;
			}

			r.start = (uint64_t)mp->gpa;
			r.end = r.start + (uint64_t)m->size;
			out_keep[n++] = r;
		}
	}

	return n;
}

static int unmap_unprotected_if_strict_gateway(const struct parsed_payload *self_cfg)
{
	struct ipa_range keep[MAX_KEEP_RANGES];
	size_t n_keep = 0;

	if (!self_cfg)
		return PVAL_EARGS;

	if (self_cfg->self_vm_index >= self_cfg->num_vms) {
		INFO("validator: unmap_unprotected: self_vm_index out of range (%u >= %u)\n",
		     self_cfg->self_vm_index, self_cfg->num_vms);
		return PVAL_ECFG_MISMATCH;
	}

	/*
	 * Apply selective unmap only for strict gateway.
	 * Others are left untouched.
	 */
	if (!(self_cfg->vms[self_cfg->self_vm_index].is_gateway &&
	      self_cfg->vms[self_cfg->self_vm_index].strict))
		return PVAL_OK;

	n_keep = collect_unprotected_keep_ranges(self_cfg, keep,
						 sizeof(keep) / sizeof(keep[0]));
	INFO("validator: unmap_unprotected(strict gateway): keep_ranges=%lu\n",
	     (unsigned long)n_keep);

	if (s2_ctx_cached) {
		INFO("validator: unmap_unprotected(strict gateway): using cached s2_ctx start_ipa=0x%lx\n",
		     cached_start_ipa);
		rmm_unmap_unprotected_ns_ctx_except(&cached_s2_ctx, cached_start_ipa,
						    keep, n_keep);
		return PVAL_OK;
	}

	uint32_t self_hash = self_cfg->vms[self_cfg->self_vm_index].hash;
	unsigned long self_rd_addr = 0;
	if (!get_peer_rd(self_hash, &self_rd_addr)) {
		INFO("validator: unmap_unprotected(strict gateway): failed to resolve self RD (hash=0x%x)\n",
		     self_hash);
		return PVAL_ECFG_MISMATCH;
	}

	struct granule *g_rd = find_lock_granule(self_rd_addr, GRANULE_STATE_RD);
	if (g_rd == NULL) {
		INFO("validator: unmap_unprotected(strict gateway): failed to lock RD granule (rd=0x%lx)\n",
		     self_rd_addr);
		return PVAL_ECFG_MISMATCH;
	}

	struct rd *rd = buffer_granule_map(g_rd, SLOT_RD2);
	if (rd == NULL) {
		INFO("validator: unmap_unprotected(strict gateway): failed to map RD (rd=0x%lx)\n",
		     self_rd_addr);
		granule_unlock(g_rd);
		return PVAL_ECFG_MISMATCH;
	}

	unsigned long start_ipa = realm_par_size(rd);
	INFO("validator: unmap_unprotected(strict gateway): start_ipa=0x%lx\n",
	     start_ipa);

	rmm_unmap_unprotected_ns_ctx_except(&rd->s2_ctx, start_ipa, keep, n_keep);

	buffer_unmap(rd);
	granule_unlock(g_rd);
	return PVAL_OK;
}

int apply_mem_actions(struct parsed_payload *self_cfg,
                      const struct sgt *sgt,
                      const char mem_name[4])
{
	int rc = activate_mem_mappings_from_sgt(self_cfg, sgt, mem_name);
	if (rc != PVAL_OK)
		return rc;

	return unmap_unprotected_if_strict_gateway(self_cfg);
}
