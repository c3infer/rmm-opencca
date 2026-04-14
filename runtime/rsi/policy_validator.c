/* policy_validator.c */
#include <policy_validator.h>


/* NOTE: Not re-entrant / not SMP-safe unless you serialize or make per-CPU. */
static struct parsed_payload peer_cfgs_buf[PARSER_MAX_MAPS];
static unsigned long peer_pds_buf[PARSER_MAX_MAPS];
static unsigned long explicit_rds_buf[PARSER_MAX_MAPS];

/* -------------------- tiny helpers -------------------- */

static const struct parsed_mem *find_mem_by_name(const struct parsed_payload *cfg,
                                                 const char name[4])
{
	if (!cfg) {
		INFO("validator: find_mem_by_name: cfg=NULL\n");
		return NULL;
	}

	for (uint16_t i = 0; i < cfg->num_mems && i < PARSER_MAX_MEMS; i++) {
		if (memcmp(cfg->mems[i].name, name, 4) == 0) {
			INFO("validator: find_mem_by_name: found mem '%c%c%c%c' at idx=%u\n",
			     name[0], name[1], name[2], name[3], i);
			return &cfg->mems[i];
		}
	}
	INFO("validator: find_mem_by_name: mem '%c%c%c%c' not found (num_mems=%u)\n",
	     name[0], name[1], name[2], name[3], cfg->num_mems);
	return NULL;
}

/* Find a VM index in cfg by hash. Returns true if found. */
static bool cfg_find_vm_index_by_hash(const struct parsed_payload *cfg,
                                      uint32_t hash,
                                      uint16_t *out_idx)
{
	if (!cfg || !out_idx) {
		INFO("validator: cfg_find_vm_index_by_hash: bad args cfg=%p out_idx=%p\n",
		     cfg, out_idx);
		return false;
	}

	for (uint16_t i = 0; i < cfg->num_vms && i < PARSER_MAX_VMS; i++) {
		if (cfg->vms[i].hash == hash) {
			*out_idx = i;
			INFO("validator: cfg_find_vm_index_by_hash: hash=0x%x -> idx=%u\n", hash, i);
			return true;
		}
	}

	INFO("validator: cfg_find_vm_index_by_hash: hash=0x%x not found (num_vms=%u)\n",
	     hash, cfg->num_vms);
	return false;
}

/* Extract canonical base GPA for the region from a mem definition. */
static bool mem_pick_base_gpa(const struct parsed_payload *cfg,
                              const struct parsed_mem *m,
                              uint64_t *out_base_gpa)
{
	if (!cfg || !m || !out_base_gpa) {
		INFO("validator: mem_pick_base_gpa: bad args cfg=%p m=%p out=%p\n",
		     cfg, m, out_base_gpa);
		return false;
	}

	/* Prefer self mapping if present; else first mapping. */
	uint16_t self = cfg->self_vm_index;

	for (uint16_t i = 0; i < m->num_mappings && i < PARSER_MAX_MAPS; i++) {
		if (m->mappings[i].vm_index == self) {
			*out_base_gpa = m->mappings[i].gpa;
			INFO("validator: mem_pick_base_gpa: self map found (self_idx=%u) base_gpa=0x%llx\n",
			     self, (unsigned long long)*out_base_gpa);
			return true;
		}
	}

	if (m->num_mappings > 0) {
		*out_base_gpa = m->mappings[0].gpa;
		INFO("validator: mem_pick_base_gpa: no self map; using first map base_gpa=0x%llx\n",
		     (unsigned long long)*out_base_gpa);
		return true;
	}

	INFO("validator: mem_pick_base_gpa: no mappings present\n");
	return false;
}

/* Does mem have an ANY mapping? If yes, returns true and fills out fields. */
static bool mem_get_any(const struct parsed_mem *m,
                        uint64_t *out_gpa,
                        uint16_t *out_prot,
                        int32_t *out_any_count,
                        uint64_t *out_any_base_gpa,
                        uint64_t *out_any_size)
{
	if (!m) {
		INFO("validator: mem_get_any: m=NULL\n");
		return false;
	}

	for (uint16_t i = 0; i < m->num_mappings && i < PARSER_MAX_MAPS; i++) {
		if (m->mappings[i].vm_index == VM_IDX_ANY) {
			const uint64_t any_base = (uint64_t)m->mappings[i].gpa;
			const uint64_t any_size = (uint64_t)m->size; /* range = whole mem size */

			if (out_gpa) *out_gpa = any_base;
			if (out_prot) *out_prot = m->mappings[i].prot;
			if (out_any_count) *out_any_count = m->mappings[i].any_count;

			if (out_any_base_gpa) *out_any_base_gpa = any_base;
			if (out_any_size) *out_any_size = any_size;

			INFO("validator: mem_get_any: found ANY base_gpa=0x%llx size=0x%llx prot=0x%x any_count=%d\n",
			     (unsigned long long)any_base,
			     (unsigned long long)any_size,
			     (unsigned)m->mappings[i].prot,
			     (int)m->mappings[i].any_count);
			return true;
		}
	}

	INFO("validator: mem_get_any: no ANY mapping\n");
	return false;
}


/*
 * Compare one memory region definition across cfgs, robust to vm_index ordering.
 */
static bool mem_def_equal_across_cfgs(const struct parsed_payload *cfg_a,
                                     const struct parsed_mem *m_a,
                                     const struct parsed_payload *cfg_b,
                                     const struct parsed_mem *m_b)
{
	if (!cfg_a || !m_a || !cfg_b || !m_b) {
		INFO("validator: mem_def_equal: bad args cfg_a=%p m_a=%p cfg_b=%p m_b=%p\n",
		     cfg_a, m_a, cfg_b, m_b);
		return false;
	}

	if (m_a->type != m_b->type) {
		INFO("validator: mem_def_equal: type mismatch a=%u b=%u\n", m_a->type, m_b->type);
		return false;
	}
	if (m_a->size != m_b->size) {
		INFO("validator: mem_def_equal: size mismatch a=0x%llx b=0x%llx\n",
		     (unsigned long long)m_a->size, (unsigned long long)m_b->size);
		return false;
	}

	/* Compare ANY fields (presence may differ; handled via coverage checks). */
	{
		uint64_t any_gpa_a = 0, any_gpa_b = 0;
		uint16_t any_prot_a = 0, any_prot_b = 0;
		int32_t any_cnt_a = 0, any_cnt_b = 0;

		/* NEW: range-aware ANY outputs */
		uint64_t any_base_a = 0, any_base_b = 0;
		uint64_t any_size_a = 0, any_size_b = 0;

		bool has_any_a = mem_get_any(m_a, &any_gpa_a, &any_prot_a, &any_cnt_a,
		                             &any_base_a, &any_size_a);
		bool has_any_b = mem_get_any(m_b, &any_gpa_b, &any_prot_b, &any_cnt_b,
		                             &any_base_b, &any_size_b);

		if (has_any_a && has_any_b) {
			if (any_gpa_a != any_gpa_b ||
			    any_prot_a != any_prot_b ||
			    any_cnt_a != any_cnt_b ||
			    any_base_a != any_base_b ||
			    any_size_a != any_size_b) {
				INFO("validator: mem_def_equal: ANY fields mismatch "
				     "a(gpa=0x%llx prot=0x%x cnt=%d base=0x%llx size=0x%llx) "
				     "b(gpa=0x%llx prot=0x%x cnt=%d base=0x%llx size=0x%llx)\n",
				     (unsigned long long)any_gpa_a, (unsigned)any_prot_a, (int)any_cnt_a,
				     (unsigned long long)any_base_a, (unsigned long long)any_size_a,
				     (unsigned long long)any_gpa_b, (unsigned)any_prot_b, (int)any_cnt_b,
				     (unsigned long long)any_base_b, (unsigned long long)any_size_b);
				return false;
			}
		}
	}

	/* For each non-ANY mapping in A, find corresponding mapping in B by VM hash.
	 * If missing in B and B has ANY, treat ANY as a normal peer for coverage.
	 */
	{
		uint64_t any_gpa_b = 0;
		uint16_t any_prot_b = 0;
		int32_t any_cnt_b = 0;
		bool has_any_b = mem_get_any(m_b, &any_gpa_b, &any_prot_b, &any_cnt_b,
		                             NULL, NULL);
		size_t covered_by_any_b = 0;

		for (uint16_t i = 0; i < m_a->num_mappings && i < PARSER_MAX_MAPS; i++) {
			const struct parsed_mapping *ma = &m_a->mappings[i];
			if (ma->vm_index == VM_IDX_ANY)
				continue;

			if (ma->vm_index >= cfg_a->num_vms) {
				INFO("validator: mem_def_equal: ma vm_index out of range: %u >= num_vms=%u\n",
				     ma->vm_index, cfg_a->num_vms);
				return false;
			}

			const struct parsed_vm *vma = &cfg_a->vms[ma->vm_index];
			uint32_t hash = vma->hash;

			uint16_t vb_idx = 0;
			if (!cfg_find_vm_index_by_hash(cfg_b, hash, &vb_idx)) {
				if (has_any_b && (ma->gpa == any_gpa_b) && (ma->prot == any_prot_b)) {
					covered_by_any_b++;
					continue;
				}
				INFO("validator: mem_def_equal: peer missing vm hash=0x%x\n", hash);
				return false;
			}

			const struct parsed_vm *vmb = &cfg_b->vms[vb_idx];
			if (vmb->is_gateway != vma->is_gateway || vmb->strict != vma->strict) {
				INFO("validator: mem_def_equal: VM props mismatch for hash=0x%x "
				     "a(gw=%u strict=%u) b(gw=%u strict=%u)\n",
				     hash, vma->is_gateway, vma->strict, vmb->is_gateway, vmb->strict);
				return false;
			}

			bool found_map = false;
			for (uint16_t j = 0; j < m_b->num_mappings && j < PARSER_MAX_MAPS; j++) {
				const struct parsed_mapping *mb = &m_b->mappings[j];
				if (mb->vm_index == vb_idx) {
					if (mb->gpa != ma->gpa || mb->prot != ma->prot) {
						INFO("validator: mem_def_equal: mapping mismatch for hash=0x%x "
						     "a(gpa=0x%llx prot=0x%x) b(gpa=0x%llx prot=0x%x)\n",
						     hash,
						     (unsigned long long)ma->gpa, (unsigned)ma->prot,
						     (unsigned long long)mb->gpa, (unsigned)mb->prot);
						return false;
					}
					found_map = true;
					break;
				}
			}
			if (!found_map) {
				if (has_any_b && (ma->gpa == any_gpa_b) && (ma->prot == any_prot_b)) {
					covered_by_any_b++;
					continue;
				}
				INFO("validator: mem_def_equal: mapping not found in peer for hash=0x%x (vb_idx=%u)\n",
				     hash, vb_idx);
				return false;
			}
		}

		if (has_any_b && any_cnt_b != -1 && covered_by_any_b > (size_t)any_cnt_b) {
			INFO("validator: mem_def_equal: peer ANY capacity exceeded "
			     "covered_by_any=%lu any_count=%d\n",
			     (unsigned long)covered_by_any_b, (int)any_cnt_b);
			return false;
		}
	}

	/* Symmetric check: allow A's ANY to cover missing explicit mappings in A. */
	{
		uint64_t any_gpa_a = 0;
		uint16_t any_prot_a = 0;
		int32_t any_cnt_a = 0;
		bool has_any_a = mem_get_any(m_a, &any_gpa_a, &any_prot_a, &any_cnt_a,
		                             NULL, NULL);
		size_t covered_by_any_a = 0;

		for (uint16_t i = 0; i < m_b->num_mappings && i < PARSER_MAX_MAPS; i++) {
			const struct parsed_mapping *mb = &m_b->mappings[i];
			if (mb->vm_index == VM_IDX_ANY)
				continue;

			if (mb->vm_index >= cfg_b->num_vms) {
				INFO("validator: mem_def_equal: mb vm_index out of range: %u >= num_vms=%u\n",
				     mb->vm_index, cfg_b->num_vms);
				return false;
			}

			const struct parsed_vm *vmb = &cfg_b->vms[mb->vm_index];
			uint32_t hash = vmb->hash;

			uint16_t va_idx = 0;
			if (!cfg_find_vm_index_by_hash(cfg_a, hash, &va_idx)) {
				if (has_any_a && (mb->gpa == any_gpa_a) && (mb->prot == any_prot_a)) {
					covered_by_any_a++;
					continue;
				}
				INFO("validator: mem_def_equal: self missing vm hash=0x%x\n", hash);
				return false;
			}

			const struct parsed_vm *vma = &cfg_a->vms[va_idx];
			if (vma->is_gateway != vmb->is_gateway || vma->strict != vmb->strict) {
				INFO("validator: mem_def_equal: VM props mismatch for hash=0x%x "
				     "a(gw=%u strict=%u) b(gw=%u strict=%u)\n",
				     hash, vma->is_gateway, vma->strict, vmb->is_gateway, vmb->strict);
				return false;
			}

			bool found_map = false;
			for (uint16_t j = 0; j < m_a->num_mappings && j < PARSER_MAX_MAPS; j++) {
				const struct parsed_mapping *ma = &m_a->mappings[j];
				if (ma->vm_index == va_idx) {
					if (ma->gpa != mb->gpa || ma->prot != mb->prot) {
						INFO("validator: mem_def_equal: mapping mismatch for hash=0x%x "
						     "a(gpa=0x%llx prot=0x%x) b(gpa=0x%llx prot=0x%x)\n",
						     hash,
						     (unsigned long long)ma->gpa, (unsigned)ma->prot,
						     (unsigned long long)mb->gpa, (unsigned)mb->prot);
						return false;
					}
					found_map = true;
					break;
				}
			}
			if (!found_map) {
				if (has_any_a && (mb->gpa == any_gpa_a) && (mb->prot == any_prot_a)) {
					covered_by_any_a++;
					continue;
				}
				INFO("validator: mem_def_equal: mapping not found in self for hash=0x%x (va_idx=%u)\n",
				     hash, va_idx);
				return false;
			}
		}

		if (has_any_a && any_cnt_a != -1 && covered_by_any_a > (size_t)any_cnt_a) {
			INFO("validator: mem_def_equal: self ANY capacity exceeded "
			     "covered_by_any=%lu any_count=%d\n",
			     (unsigned long)covered_by_any_a, (int)any_cnt_a);
			return false;
		}
	}

	INFO("validator: mem_def_equal: OK\n");
	return true;
}


/* -------------------- SGT checks -------------------- */
/* Build explicit RD allowlist AND per-RD GPA base (from mem mappings). */
static size_t build_explicit_rd_base_list(const struct parsed_payload *cfg,
                                         const struct parsed_mem *m,
                                         unsigned long *out_rds,
                                         uint64_t *out_bases,
                                         size_t cap)
{
	size_t n = 0;

	if (!cfg || !m || !out_rds || !out_bases || cap == 0)
		return 0;

	for (uint16_t i = 0; i < m->num_mappings && i < PARSER_MAX_MAPS; i++) {
		const struct parsed_mapping *mp = &m->mappings[i];
		uint32_t hash;
		unsigned long rd;

		if (mp->vm_index == VM_IDX_ANY)
			continue;
		if (mp->vm_index >= cfg->num_vms)
			continue;

		hash = cfg->vms[mp->vm_index].hash;

		if (!get_peer_rd(hash, &rd)) {
			INFO("validator: build_explicit_rd_base_list: hash=0x%x -> RD resolution failed\n", hash);
			continue;
		}

		/* De-dup by RD */
		bool dup = false;
		for (size_t k = 0; k < n; k++) {
			if (out_rds[k] == rd) { dup = true; break; }
		}
		if (dup)
			continue;

		if (n >= cap)
			break;

		out_rds[n]   = rd;
		out_bases[n] = (uint64_t)mp->gpa;

		INFO("validator: build_explicit_rd_base_list: add rd=0x%lx base=0x%llx (hash=0x%x)\n",
		     rd, (unsigned long long)out_bases[n], hash);

		n++;
	}

	INFO("validator: build_explicit_rd_base_list: n_explicit=%lu\n", (unsigned long)n);
	return n;
}

bool get_peer_rd(uint32_t peer_hash, unsigned long *out_rd)
{
	if (!out_rd) {
		INFO("validator: get_peer_rd: out_rd=NULL\n");
		return false;
	}

	INFO("validator: get_peer_rd: hash=0x%x\n", peer_hash);

	type_rim_t ret;
	if (!ram_get_entry_from_hash(peer_hash, &ret)) {
		INFO("validator: get_peer_rd: ram_get_entry_from_hash failed (hash=0x%x)\n", peer_hash);
		return false;
	}

	*out_rd = ret.rd_addr;
	INFO("validator: get_peer_rd: hash=0x%x -> rd=0x%lx\n", peer_hash, *out_rd);
	return true;
}

bool get_peer_pd_addr(unsigned long peer_rd, unsigned long *out_pd_addr)
{
	if (!out_pd_addr) {
		INFO("validator: get_peer_pd_addr: out_pd_addr=NULL\n");
		return false;
	}

	INFO("validator: get_peer_pd_addr: rd=0x%lx\n", peer_rd);

	type_rim_t ret;
	if (!ram_get_entry_from_rd(peer_rd, &ret)) {
		INFO("validator: get_peer_pd_addr: ram_get_entry_from_rd failed (rd=0x%lx)\n", peer_rd);
		return false;
	}

	*out_pd_addr = ret.pd_addr;
	INFO("validator: get_peer_pd_addr: rd=0x%lx -> pd=0x%lx\n", peer_rd, *out_pd_addr);
	return true;
}

struct page_pair { uint64_t gpa; unsigned long pa; };

/* ---------------- Small helpers (O(n)) ---------------- */
/* Assumes:
 *   INFO(fmt, ...)
 *   PVAL_* error codes
 *   struct sgt { size_t count; struct sgt_entry entries[]; }
 *   struct sgt_entry { uint64_t gpa; unsigned long pa; unsigned long rd; }
 */

static bool set_contains_ulong(const unsigned long *set, size_t n, unsigned long v)
{
	for (size_t i = 0; i < n; i++)
		if (set[i] == v) return true;
	return false;
}

static bool set_contains_u64(const uint64_t *set, size_t n, uint64_t v)
{
	for (size_t i = 0; i < n; i++)
		if (set[i] == v) return true;
	return false;
}

static int set_add_ulong_strict(unsigned long *set, size_t *n, size_t cap, unsigned long v)
{
	if (set_contains_ulong(set, *n, v))
		return 0;
	if (*n >= cap)
		return -1;
	set[(*n)++] = v;
	return 0;
}

static bool rd_is_explicit(unsigned long rd, const unsigned long *explicit_rds, size_t n_explicit)
{
	for (size_t i = 0; i < n_explicit; i++)
		if (explicit_rds[i] == rd) return true;
	return false;
}

static int validate_memobj_args(const struct sgt *sgt,
                               uint64_t size,
                               const unsigned long *explicit_rds,
                               const uint64_t *explicit_bases,
                               size_t n_explicit)
{
	if (!sgt || size == 0 || !explicit_rds || !explicit_bases || n_explicit == 0)
		return PVAL_EARGS;

	const uint64_t step = (uint64_t)GRANULE_SIZE;
	if ((size % step) != 0)
		return PVAL_ESGT_COVERAGE;

	const uint64_t n_pages = size / step;
	if (n_pages > SGT_MAX_ENTRIES)
		return PVAL_ESGT_COVERAGE;

	return PVAL_OK;
}

/* Lookup PA for exact (rd, gpa). No region filter because per-RD base determines scope. */
static bool find_pa_for_rd_gpa(const struct sgt *sgt,
                              unsigned long rd,
                              uint64_t gpa,
                              unsigned long *out_pa)
{
	for (size_t i = 0; i < sgt->count; i++) {
		const struct sgt_entry *e = &sgt->entries[i];
		if ((uint64_t)e->gpa != gpa)
			continue;
		if (e->rd != rd)
			continue;
		*out_pa = e->pa;
		return true;
	}
	return false;
}

/* Phase A:
 *  - coverage per explicit RD for its configured window
 *  - page-index PA consistency across explicit RDs
 *  - build PA-set (union) for the memory object
 */
static int build_memobj_pa_set_and_check_consistency(const struct sgt *sgt,
                                                    uint64_t size,
                                                    const unsigned long *explicit_rds,
                                                    const uint64_t *explicit_bases,
                                                    size_t n_explicit,
                                                    unsigned long *pa_set,
                                                    size_t *n_pa_set,
                                                    size_t pa_cap)
{
	const uint64_t step = (uint64_t)GRANULE_SIZE;
	const uint64_t n_pages = size / step;

	/* Canonical PA per page index (static to avoid EL2 stack blowups). */
	static unsigned long canonical_pa[SGT_MAX_ENTRIES];
	static bool canonical_set[SGT_MAX_ENTRIES];

	for (uint64_t k = 0; k < n_pages; k++) {
		canonical_set[k] = false;
		canonical_pa[k] = 0;
	}

	*n_pa_set = 0;

	for (size_t e = 0; e < n_explicit; e++) {
		const unsigned long rd = explicit_rds[e];
		const uint64_t base = explicit_bases[e];

		for (uint64_t k = 0; k < n_pages; k++) {
			const uint64_t gpa = base + k * step;
			unsigned long pa = 0;

			if (!find_pa_for_rd_gpa(sgt, rd, gpa, &pa)) {
				INFO("validator: validate_sgt(obj): coverage miss rd=0x%lx gpa=0x%llx\n",
				     rd, (unsigned long long)gpa);
				return PVAL_ESGT_COVERAGE;
			}

			/* page-index consistency */
			if (!canonical_set[k]) {
				canonical_set[k] = true;
				canonical_pa[k] = pa;
			} else if (canonical_pa[k] != pa) {
				INFO("validator: validate_sgt(obj): conflict page_idx=%llu pa_a=0x%lx pa_b=0x%lx\n",
				     (unsigned long long)k, canonical_pa[k], pa);
				return PVAL_ESGT_CONFLICT;
			}

			if (set_add_ulong_strict(pa_set, n_pa_set, pa_cap, pa) != 0) {
				INFO("validator: validate_sgt(obj): pa_set overflow (n_pa_set=%lu)\n",
				     (unsigned long)*n_pa_set);
				return PVAL_ESGT_COVERAGE;
			}
		}
	}

	return PVAL_OK;
}

/* Phase B:
 * Global PA exclusivity for the object's PA-set:
 *  - explicit RDs: always allowed anywhere
 *  - non-explicit: allowed only via ANY (global GPA set + any_count cap)
 */
static int enforce_memobj_pa_exclusivity(const struct sgt *sgt,
                                        const unsigned long *pa_set,
                                        size_t n_pa_set,
                                        const unsigned long *explicit_rds,
                                        size_t n_explicit,
                                        bool has_any,
                                        int32_t any_count,
                                        const uint64_t *any_gpas,
                                        size_t n_any_gpas)
{
	unsigned long extra_rds[64];
	size_t n_extra_rds = 0;

	for (size_t i = 0; i < sgt->count; i++) {
		const struct sgt_entry *e = &sgt->entries[i];
		const unsigned long pa = e->pa;

		if (!set_contains_ulong(pa_set, n_pa_set, pa))
			continue;

		const unsigned long rd = e->rd;
		const uint64_t gpa = (uint64_t)e->gpa;

		if (rd_is_explicit(rd, explicit_rds, n_explicit))
			continue;

		if (!has_any) {
			INFO("validator: validate_sgt(obj): illegal extra rd=0x%lx maps obj-pa=0x%lx at gpa=0x%llx (no ANY)\n",
			     rd, pa, (unsigned long long)gpa);
			return PVAL_ESGT_RD_ILLEGAL;
		}

		/* Global ANY GPA restriction if list provided. */
		if (any_gpas && n_any_gpas != 0 && !set_contains_u64(any_gpas, n_any_gpas, gpa)) {
			INFO("validator: validate_sgt(obj): extra rd=0x%lx maps obj-pa=0x%lx at gpa=0x%llx not in ANY set\n",
			     rd, pa, (unsigned long long)gpa);
			return PVAL_ESGT_RD_ILLEGAL;
		}

		/* Track distinct extra RDs and enforce any_count. */
		if (!set_contains_ulong(extra_rds, n_extra_rds, rd)) {
			if (n_extra_rds < (sizeof(extra_rds)/sizeof(extra_rds[0]))) {
				extra_rds[n_extra_rds++] = rd;
			} else {
				if (any_count != -1) {
					INFO("validator: validate_sgt(obj): extra_rds overflow (cap=%d) rd=0x%lx\n",
					     (int)any_count, rd);
					return PVAL_ESGT_RD_ILLEGAL;
				}
			}

			if (any_count != -1 && n_extra_rds > (size_t)any_count) {
				INFO("validator: validate_sgt(obj): ANY extra-rd cap exceeded n_extra=%lu any_count=%d\n",
				     (unsigned long)n_extra_rds, (int)any_count);
				return PVAL_ESGT_RD_ILLEGAL;
			}
		}
	}

	return PVAL_OK;
}

/* ---------------- Top-level: validate_sgt_for_mem_object() ----------- */

static int validate_sgt_for_mem_object(const struct sgt *sgt,
                                      uint64_t size,
                                      const unsigned long *explicit_rds,
                                      const uint64_t *explicit_bases,
                                      size_t n_explicit,
                                      bool has_any,
                                      int32_t any_count,
                                      const uint64_t *any_gpas,
                                      size_t n_any_gpas)
{
	int rc = validate_memobj_args(sgt, size, explicit_rds, explicit_bases, n_explicit);
	if (rc != PVAL_OK)
		return rc;

	/* Large scratch kept static to avoid EL2 stack overflow. */
	static unsigned long pa_set[SGT_MAX_ENTRIES];
	size_t n_pa_set = 0;

	INFO("validator: validate_sgt(obj): size=0x%llx explicit=%lu has_any=%d any_count=%d n_any_gpas=%lu\n",
	     (unsigned long long)size,
	     (unsigned long)n_explicit,
	     (int)has_any, (int)any_count,
	     (unsigned long)n_any_gpas);

	rc = build_memobj_pa_set_and_check_consistency(sgt, size,
	                                               explicit_rds, explicit_bases, n_explicit,
	                                               pa_set, &n_pa_set,
	                                               (sizeof(pa_set)/sizeof(pa_set[0])));
	if (rc != PVAL_OK)
		return rc;

	rc = enforce_memobj_pa_exclusivity(sgt,
	                                   pa_set, n_pa_set,
	                                   explicit_rds, n_explicit,
	                                   has_any, any_count,
	                                   any_gpas, n_any_gpas);
	if (rc != PVAL_OK)
		return rc;

	INFO("validator: validate_sgt(obj): OK (pa_set=%lu)\n", (unsigned long)n_pa_set);
	return PVAL_OK;
}

/* -------------------- main API -------------------- */

static int validate_mem_and_load_peers(struct parsed_payload *self_cfg,
                                       unsigned long self_pd_addr,
                                       const struct sgt *sgt,
                                       const char mem_name[4],
                                       uint64_t *out_base_gpa,
                                       struct parsed_payload **out_peer_cfgs,
                                       unsigned long **out_peer_pds,
                                       size_t *out_n_loaded)
{
	const struct parsed_mem *m0;
	uint64_t base_gpa;
	int32_t any_count = 0;
	bool has_any;

	struct parsed_payload *peer_cfgs = peer_cfgs_buf;
	unsigned long *peer_pds = peer_pds_buf;
	unsigned long *explicit_rds = explicit_rds_buf;
	static uint64_t explicit_bases_buf[PARSER_MAX_MAPS]; /* NEW */
	uint64_t *explicit_bases = explicit_bases_buf;       /* NEW */
	size_t n_loaded = 0;

	m0 = find_mem_by_name(self_cfg, mem_name);
	if (!m0)
		return PVAL_ENOMEM_NOTFOUND;

	if (m0->type != MEM_PROTECTED)
		return PVAL_ENOMEM_NOTFOUND;

	if (!mem_pick_base_gpa(self_cfg, m0, &base_gpa))
		return PVAL_ECFG_MISMATCH;

	/* NEW: range-aware ANY extraction */
	uint64_t any_gpa = 0;
	uint16_t any_prot = 0;
	uint64_t any_base_gpa = 0;
	uint64_t any_size = 0;

	has_any = mem_get_any(m0, &any_gpa, &any_prot, &any_count,
	                      &any_base_gpa, &any_size);

	INFO("validator: mem '%c%c%c%c' size=0x%llx base_gpa=0x%llx has_any=%d any_count=%d num_mappings=%u\n",
	     mem_name[0], mem_name[1], mem_name[2], mem_name[3],
	     (unsigned long long)m0->size,
	     (unsigned long long)base_gpa,
	     (int)has_any, (int)any_count,
	     (unsigned)m0->num_mappings);

	/* init buffers */
	for (size_t i = 0; i < PARSER_MAX_MAPS; i++) {
		peer_pds[i] = 0;
		explicit_rds[i] = 0;
		explicit_bases[i] = 0; /* NEW */
	}

	/* load peer cfgs (best-effort) */
	for (uint16_t i = 0; i < m0->num_mappings && i < PARSER_MAX_MAPS; i++) {
		const struct parsed_mapping *mp = &m0->mappings[i];
		uint32_t hash;
		unsigned long rd, pd;
		bool dup;

		if (mp->vm_index == VM_IDX_ANY)
			continue;
		if (mp->vm_index >= self_cfg->num_vms)
			return PVAL_ECFG_MISMATCH;

		hash = self_cfg->vms[mp->vm_index].hash;

		if (!get_peer_rd(hash, &rd))
			continue;
		if (!get_peer_pd_addr(rd, &pd))
			continue;

		/* do not load self as peer */
		if (self_pd_addr && pd == self_pd_addr) {
			INFO("validator: peer_scan: skip peer hash=0x%x rd=0x%lx (pd==self)\n",
			     hash, rd);
			continue;
		}

		dup = false;
		for (size_t k = 0; k < n_loaded; k++) {
			if (peer_pds[k] == pd) { dup = true; break; }
		}
		if (dup)
			continue;

		if (!load_cfg(pd, &peer_cfgs[n_loaded],
		              GRANULE_STATE_DELEGATED, SLOT_DELEGATED)) {
			INFO("validator: skipping peer hash=0x%x rd=0x%lx (load_cfg failed)\n",
			     hash, rd);
			continue;
		}

		peer_pds[n_loaded++] = pd;
		if (n_loaded >= PARSER_MAX_MAPS)
			break;
	}

	/* cross-check (best-effort) */
	if (n_loaded == 0) {
		INFO("validator: no peers loaded for cross-check; continuing\n");
	} else {
		for (size_t i = 0; i < n_loaded; i++) {
			const struct parsed_mem *pm =
				find_mem_by_name(&peer_cfgs[i], mem_name);
			if (!pm)
				return PVAL_ECFG_MISMATCH;
			if (!mem_def_equal_across_cfgs(self_cfg, m0,
			                               &peer_cfgs[i], pm))
				return PVAL_ECFG_MISMATCH;
		}
	}

	/* Build explicit allowlist + per-explicit base GPAs (NEW) */
	size_t n_explicit = build_explicit_rd_base_list(self_cfg, m0,
	                                                explicit_rds, explicit_bases,
	                                                PARSER_MAX_MAPS);

	/* NEW: build ANY GPA list from ANY range (per-page GPAs) */
	const uint64_t *any_gpas = NULL;
	size_t n_any_gpas = 0;
	static uint64_t any_gpas_buf[PARSER_MAX_MAPS];

	if (has_any) {
		const uint64_t step = (uint64_t)GRANULE_SIZE;

		if ((any_size % step) != 0) {
			INFO("validator: mem_get_any: ANY size not granule-multiple size=0x%llx step=0x%llx\n",
			     (unsigned long long)any_size, (unsigned long long)step);
			return PVAL_ECFG_MISMATCH;
		}

		/* Expand into per-page GPAs (bounded). */
		uint64_t n_pages = any_size / step;
		if (n_pages > PARSER_MAX_MAPS)
			n_pages = PARSER_MAX_MAPS;

		for (uint64_t i = 0; i < n_pages; i++) {
			any_gpas_buf[n_any_gpas++] = any_base_gpa + i * step;
		}

		any_gpas = any_gpas_buf;

		INFO("validator: ANY range expanded: base=0x%llx size=0x%llx pages=%lu\n",
		     (unsigned long long)any_base_gpa,
		     (unsigned long long)any_size,
		     (unsigned long)n_any_gpas);
	}

	/* SGT validity (UPDATED CALL) */
	{
		int rc = validate_sgt_for_mem_object(sgt, m0->size,
		                                     explicit_rds, explicit_bases, n_explicit,
		                                     has_any, any_count,
		                                     any_gpas, n_any_gpas);
		if (rc != PVAL_OK)
			return rc;
	}

	/* outputs */
	*out_base_gpa  = base_gpa;
	*out_peer_cfgs = peer_cfgs;
	*out_peer_pds  = peer_pds;
	*out_n_loaded  = n_loaded;

	return PVAL_OK;
}

/* Check CF/transition compatibility across self + loaded peers.
 * Ensures that for each (owner_vm_index,type,range) the policy value is identical
 * across self and all loaded peers. Returns PVAL_OK or PVAL_ECFG_MISMATCH.
 */
static int check_cf_compatibility(const struct parsed_payload *self_cfg,
								  struct parsed_payload *peer_cfgs,
								  size_t n_loaded)
{
	if (!self_cfg)
		return PVAL_EARGS;

	struct {
		uint16_t owner;
		uint16_t type;
		uint32_t range;
		uint16_t policy;
	} cfmap[(PARSER_MAX_MAPS + 1) * PARSER_MAX_CFS * PARSER_MAX_CF_RANGE];
	size_t cfmap_n = 0;

	/* Add self CFs first */
	for (size_t ci = 0; ci < (size_t)self_cfg->num_cfs; ci++) {
		const struct parsed_cf *cf = &self_cfg->cfs[ci];
		for (size_t ri = 0; ri < (size_t)cf->range_len; ri++) {
			uint32_t r = cf->range[ri];
			bool found = false;
			for (size_t k = 0; k < cfmap_n; k++) {
				if (cfmap[k].owner == cf->owner_vm_index && cfmap[k].type == cf->type && cfmap[k].range == r) {
					found = true;
					if (cfmap[k].policy != cf->policy) {
						INFO("validator: CF policy conflict for owner=%u type=%u range=%u existing=%u self=%u\n",
							 (unsigned)cf->owner_vm_index, (unsigned)cf->type, (unsigned)r,
							 (unsigned)cfmap[k].policy, (unsigned)cf->policy);
						return PVAL_ECFG_MISMATCH;
					}
					break;
				}
			}
			if (!found) {
				if (cfmap_n >= (sizeof(cfmap)/sizeof(cfmap[0]))) {
					INFO("validator: CF map overflow when adding self CF\n");
					return PVAL_ECFG_MISMATCH;
				}
				cfmap[cfmap_n].owner = cf->owner_vm_index;
				cfmap[cfmap_n].type = cf->type;
				cfmap[cfmap_n].range = r;
				cfmap[cfmap_n].policy = cf->policy;
				cfmap_n++;
			}
		}
	}

	/* Now iterate peers and check/add their CFs */
	for (size_t p = 0; p < n_loaded; p++) {
		const struct parsed_payload *pc = &peer_cfgs[p];
		for (size_t ci = 0; ci < (size_t)pc->num_cfs; ci++) {
			const struct parsed_cf *cf = &pc->cfs[ci];
			for (size_t ri = 0; ri < (size_t)cf->range_len; ri++) {
				uint32_t r = cf->range[ri];
				bool found = false;
				for (size_t k = 0; k < cfmap_n; k++) {
					if (cfmap[k].owner == cf->owner_vm_index && cfmap[k].type == cf->type && cfmap[k].range == r) {
						found = true;
						if (cfmap[k].policy != cf->policy) {
							INFO("validator: CF policy conflict for owner=%u type=%u range=%u existing=%u peer=%u peer_idx=%lu\n",
								 (unsigned)cf->owner_vm_index, (unsigned)cf->type, (unsigned)r,
								 (unsigned)cfmap[k].policy, (unsigned)cf->policy, (unsigned long)p);
							return PVAL_ECFG_MISMATCH;
						}
						break;
					}
				}
				if (!found) {
					if (cfmap_n >= (sizeof(cfmap)/sizeof(cfmap[0]))) {
						INFO("validator: CF map overflow when adding peer CF\n");
						return PVAL_ECFG_MISMATCH;
					}
					cfmap[cfmap_n].owner = cf->owner_vm_index;
					cfmap[cfmap_n].type = cf->type;
					cfmap[cfmap_n].range = r;
					cfmap[cfmap_n].policy = cf->policy;
					cfmap_n++;
				}
			}
		}
	}

	/* Record unique tuples in the global transition table (non-strict by default).
	 * This tracks the validated (owner,type,range)->policy entries for later use.
	 */
	for (size_t k = 0; k < cfmap_n; k++) {
		int trc = transition_table_add(cfmap[k].owner, cfmap[k].type, cfmap[k].range, cfmap[k].policy, false, NULL, 0);
		if (trc == -1) {
			INFO("validator: CF transition table overflow when adding tuple owner=%u type=%u range=%u\n",
			     (unsigned)cfmap[k].owner, (unsigned)cfmap[k].type, (unsigned)cfmap[k].range);
			return PVAL_ECFG_MISMATCH;
		} else if (trc == -2) {
			INFO("validator: CF transition table policy mismatch when adding tuple owner=%u type=%u range=%u\n",
			     (unsigned)cfmap[k].owner, (unsigned)cfmap[k].type, (unsigned)cfmap[k].range);
			return PVAL_ECFG_MISMATCH;
		} else if (trc == -3) {
			INFO("validator: CF transition table peer conflict: non-strict CF conflicts with strict payload\n");
			return PVAL_ECFG_MISMATCH;
		}
	}
	transition_table_pretty_print();

	return PVAL_OK;
}


int validate_and_activate_mem(struct parsed_payload *self_cfg,
                              unsigned long self_pd_addr,
                              const struct sgt *sgt,
                              const char mem_name[4])
{
	uint64_t base_gpa;
	struct parsed_payload *peer_cfgs;
	unsigned long *peer_pds;
	size_t n_loaded;
	int rc;

	if (!self_cfg || !sgt || !mem_name)
		return PVAL_EARGS;

	INFO("validator: validate_and_activate_mem: begin mem='%c%c%c%c' self_pd=0x%lx\n",
	     mem_name[0], mem_name[1], mem_name[2], mem_name[3], self_pd_addr);

	rc = validate_mem_and_load_peers(self_cfg, self_pd_addr, sgt,
	                                 mem_name,
	                                 &base_gpa,
	                                 &peer_cfgs,
	                                 &peer_pds,
	                                 &n_loaded);
	if (rc != PVAL_OK)
		return rc;

	/* Check CF/transition compatibility across self + loaded peers */
	if ( (rc = check_cf_compatibility(self_cfg, peer_cfgs, n_loaded)) != PVAL_OK)
		return rc;

	(void)self_pd_addr;
	(void)base_gpa;
	(void)peer_pds;
	(void)n_loaded;
	return apply_mem_actions(self_cfg, sgt, mem_name);
}

/* Strict CF compatibility check: validates CF tuples across self + peers,
 * checks for conflicts with non-strict table entries, adds them to the table,
 * and marks them as strict. Returns PVAL_OK or PVAL_ECFG_MISMATCH.
 */
static int check_cf_compatibility_strict(const struct parsed_payload *self_cfg,
										struct parsed_payload *peer_cfgs,
										size_t n_loaded)
{
	if (!self_cfg)
		return PVAL_EARGS;

	/* Build CF map from self + peers */
	struct {
		uint16_t owner;
		uint16_t type;
		uint32_t range;
		uint16_t policy;
	} cfmap[(PARSER_MAX_MAPS + 1) * PARSER_MAX_CFS * PARSER_MAX_CF_RANGE];
	size_t cfmap_n = 0;

	/* Collect CFs from self */
	for (size_t ci = 0; ci < (size_t)self_cfg->num_cfs; ci++) {
		const struct parsed_cf *cf = &self_cfg->cfs[ci];
		for (size_t ri = 0; ri < (size_t)cf->range_len; ri++) {
			uint32_t r = cf->range[ri];
			bool found = false;
			for (size_t k = 0; k < cfmap_n; k++) {
				if (cfmap[k].owner == cf->owner_vm_index && cfmap[k].type == cf->type && cfmap[k].range == r) {
					found = true;
					if (cfmap[k].policy != cf->policy) {
						INFO("validator: strict CF policy conflict for owner=%u type=%u range=%u existing=%u self=%u\n",
							 (unsigned)cf->owner_vm_index, (unsigned)cf->type, (unsigned)r,
							 (unsigned)cfmap[k].policy, (unsigned)cf->policy);
						return PVAL_ECFG_MISMATCH;
					}
					break;
				}
			}
			if (!found) {
				if (cfmap_n >= (sizeof(cfmap)/sizeof(cfmap[0]))) {
					INFO("validator: strict CF map overflow when adding self CF\n");
					return PVAL_ECFG_MISMATCH;
				}
				cfmap[cfmap_n].owner = cf->owner_vm_index;
				cfmap[cfmap_n].type = cf->type;
				cfmap[cfmap_n].range = r;
				cfmap[cfmap_n].policy = cf->policy;
				cfmap_n++;
			}
		}
	}

	/* Collect CFs from peers */
	for (size_t p = 0; p < n_loaded; p++) {
		const struct parsed_payload *pc = &peer_cfgs[p];
		for (size_t ci = 0; ci < (size_t)pc->num_cfs; ci++) {
			const struct parsed_cf *cf = &pc->cfs[ci];
			for (size_t ri = 0; ri < (size_t)cf->range_len; ri++) {
				uint32_t r = cf->range[ri];
				bool found = false;
				for (size_t k = 0; k < cfmap_n; k++) {
					if (cfmap[k].owner == cf->owner_vm_index && cfmap[k].type == cf->type && cfmap[k].range == r) {
						found = true;
						if (cfmap[k].policy != cf->policy) {
							INFO("validator: strict CF policy conflict for owner=%u type=%u range=%u existing=%u peer=%u peer_idx=%lu\n",
								 (unsigned)cf->owner_vm_index, (unsigned)cf->type, (unsigned)r,
								 (unsigned)cfmap[k].policy, (unsigned)cf->policy, (unsigned long)p);
							return PVAL_ECFG_MISMATCH;
						}
						break;
					}
				}
				if (!found) {
					if (cfmap_n >= (sizeof(cfmap)/sizeof(cfmap[0]))) {
						INFO("validator: strict CF map overflow when adding peer CF\n");
						return PVAL_ECFG_MISMATCH;
					}
					cfmap[cfmap_n].owner = cf->owner_vm_index;
					cfmap[cfmap_n].type = cf->type;
					cfmap[cfmap_n].range = r;
					cfmap[cfmap_n].policy = cf->policy;
					cfmap_n++;
				}
			}
		}
	}

	/* Check that no non-strict table entries conflict with this validation */
	{
		uint16_t owners[cfmap_n];
		uint16_t types[cfmap_n];
		uint32_t ranges[cfmap_n];
		for (size_t k = 0; k < cfmap_n; k++) {
			owners[k] = cfmap[k].owner;
			types[k] = cfmap[k].type;
			ranges[k] = cfmap[k].range;
		}
		int trc = transition_table_strict_check_no_conflicts(owners, types, ranges, cfmap_n);
		if (trc != 0) {
			INFO("validator: strict mode: transition table conflict with validated CFs\n");
			return PVAL_ECFG_MISMATCH;
		}
	}

	/* Add tuples to transition table (non-strict initially, will be marked strict below).
	 * Collect all peer hashes from self_cfg to record the strict peer group.
	 */
	uint32_t peer_hashes[PARSER_MAX_VMS];
	uint16_t peer_count = 0;
	for (uint16_t i = 0; i < self_cfg->num_vms && i < PARSER_MAX_VMS; i++) {
		if (i != self_cfg->self_vm_index) {  /* Exclude self */
			peer_hashes[peer_count++] = self_cfg->vms[i].hash;
		}
	}

	for (size_t k = 0; k < cfmap_n; k++) {
		int trc = transition_table_add(cfmap[k].owner, cfmap[k].type, cfmap[k].range, cfmap[k].policy, false, peer_hashes, peer_count);
		if (trc == -1) {
			INFO("validator: strict CF transition table overflow when adding tuple owner=%u type=%u range=%u\n",
			     (unsigned)cfmap[k].owner, (unsigned)cfmap[k].type, (unsigned)cfmap[k].range);
			return PVAL_ECFG_MISMATCH;
		} else if (trc == -2) {
			INFO("validator: strict CF transition table policy mismatch when adding tuple owner=%u type=%u range=%u\n",
			     (unsigned)cfmap[k].owner, (unsigned)cfmap[k].type, (unsigned)cfmap[k].range);
			return PVAL_ECFG_MISMATCH;
		} else if (trc == -3) {
			INFO("validator: strict CF transition table peer conflict when adding tuple owner=%u type=%u range=%u\n",
			     (unsigned)cfmap[k].owner, (unsigned)cfmap[k].type, (unsigned)cfmap[k].range);
			return PVAL_ECFG_MISMATCH;
		}
	}	/* Mark all validated tuples as strict */
	{
		uint16_t owners[cfmap_n];
		uint16_t types[cfmap_n];
		uint32_t ranges[cfmap_n];
		for (size_t k = 0; k < cfmap_n; k++) {
			owners[k] = cfmap[k].owner;
			types[k] = cfmap[k].type;
			ranges[k] = cfmap[k].range;
		}
		int trc = transition_table_mark_entries_strict(owners, types, ranges, cfmap_n);
		if (trc != 0) {
			INFO("validator: strict: failed to mark CF tuples as strict\n");
			return PVAL_ECFG_MISMATCH;
		}
	}
	transition_table_pretty_print();

	return PVAL_OK;
}

/* Strict variant: same validations as validate_and_activate_mem(), but also ensure
 * there are no SGT mappings involving self beyond those listed in the config, AND
 * there are no conflicting CF transitions in the table from previous validations.
 */
static int validate_and_activate_mem_strict(struct parsed_payload *self_cfg,
										   unsigned long self_pd_addr,
										   const struct sgt *sgt,
										   const char mem_name[4])
{
	uint64_t base_gpa;
	struct parsed_payload *peer_cfgs;
	unsigned long *peer_pds;
	size_t n_loaded;
	int rc;

	if (!self_cfg || !sgt || !mem_name)
		return PVAL_EARGS;

	INFO("validator: validate_and_activate_mem_strict: begin mem='%c%c%c%c' self_pd=0x%lx\n",
		 mem_name[0], mem_name[1], mem_name[2], mem_name[3], self_pd_addr);

	rc = validate_mem_and_load_peers(self_cfg, self_pd_addr, sgt,
									 mem_name,
									 &base_gpa,
									 &peer_cfgs,
									 &peer_pds,
									 &n_loaded);
	if (rc != PVAL_OK)
		return rc;

	/* Additional strict SGT check: ensure SGT contains no mappings for self's RD
	 * that refer to this memory object except those explicitly listed for self
	 * in the mem's mappings.
	 */
	const struct parsed_mem *m = find_mem_by_name(self_cfg, mem_name);
	if (!m)
		return PVAL_ECFG_MISMATCH;

	uint16_t self_idx = self_cfg->self_vm_index;
	uint32_t self_hash = self_cfg->vms[self_idx].hash;
	unsigned long self_rd = 0;
	if (!get_peer_rd(self_hash, &self_rd)) {
		INFO("validator: strict check: failed to resolve self RD (hash=0x%x)\n", self_hash);
		return PVAL_ECFG_MISMATCH;
	}

	/* Build mapping ranges for the object (all mappings) and for self-specific mappings. */
	uint64_t map_starts[PARSER_MAX_MAPS];
	uint64_t map_ends[PARSER_MAX_MAPS];
	uint64_t self_starts[PARSER_MAX_MAPS];
	uint64_t self_ends[PARSER_MAX_MAPS];
	size_t map_n = 0, self_n = 0;

	for (uint16_t i = 0; i < m->num_mappings && i < PARSER_MAX_MAPS; i++) {
		const struct parsed_mapping *mp = &m->mappings[i];

		/* ANY mapping is treated below via mem_get_any (covers whole mem range). */
		if (mp->vm_index == VM_IDX_ANY)
			continue;

		uint64_t start = (uint64_t)mp->gpa;
		uint64_t end = start + m->size;

		map_starts[map_n] = start;
		map_ends[map_n] = end;
		map_n++;

		if (mp->vm_index == self_idx) {
			self_starts[self_n] = start;
			self_ends[self_n] = end;
			self_n++;
		}
	}

	/* Handle ANY mapping ranges (if any) as mapping covers whole mem at any_base,size */
	uint64_t any_base = 0, any_size = 0;
	uint16_t any_prot = 0;
	int32_t any_count = 0;
	bool has_any = mem_get_any(m, NULL, &any_prot, &any_count, &any_base, &any_size);
	if (has_any) {
		uint64_t start = any_base;
		uint64_t end = any_base + any_size;
		if (map_n < PARSER_MAX_MAPS) {
			map_starts[map_n] = start;
			map_ends[map_n] = end;
			map_n++;
		}
		/* If ANY belongs to self (vm_index==VM_IDX_ANY doesn't have self mapping),
		 * there are no explicit self ranges to add here.
		 */
	}

	/* Now inspect SGT entries: any SGT entry whose GPA falls within any mapping range
	 * and whose RD == self_rd must also fall within a self mapping range; otherwise
	 * it's an extra mapping involving self and is illegal in strict mode.
	 */
	for (size_t e = 0; e < sgt->count; e++) {
		const struct sgt_entry *se = &sgt->entries[e];
		uint64_t gpa = (uint64_t)se->gpa;

		bool in_obj = false;
		for (size_t k = 0; k < map_n; k++) {
			if (gpa >= map_starts[k] && gpa < map_ends[k]) { in_obj = true; break; }
		}
		if (!in_obj)
			continue; /* SGT entry not related to this mem object */

		if (se->rd != self_rd)
			continue; /* mapping doesn't involve self */

		/* If it involves self, ensure it is within one of the explicit self ranges. */
		bool in_self = false;
		for (size_t k = 0; k < self_n; k++) {
			if (gpa >= self_starts[k] && gpa < self_ends[k]) { in_self = true; break; }
		}

		if (!in_self) {
			INFO("validator: strict SGT check: illegal extra self RD mapping rd=0x%lx gpa=0x%llx mem='%c%c%c%c'\n",
				 se->rd, (unsigned long long)gpa, mem_name[0], mem_name[1], mem_name[2], mem_name[3]);
			return PVAL_ESGT_RD_ILLEGAL;
		}
	}

	/* CF/transition checks in strict mode via dedicated function */
	rc = check_cf_compatibility_strict(self_cfg, peer_cfgs, n_loaded);
	if (rc != PVAL_OK)
		return rc;

	(void)self_pd_addr;
	(void)base_gpa;
	(void)peer_pds;
	(void)n_loaded;
	return apply_mem_actions(self_cfg, sgt, mem_name);
}

static struct sgt loaded_sgt;
static unsigned long loaded_sgt_addrs[MAX_SGT_GRANULES_ENTRIES];

static int validate_and_activate_strict(struct parsed_payload *self_cfg,
                                        unsigned long self_pd_addr)
{
	INFO("validator: validate_and_activate_strict: begin self_pd=0x%lx num_mems=%u\n",
	     self_pd_addr, self_cfg->num_mems);

	if (!sgt_load_into_and_dump(&loaded_sgt, loaded_sgt_addrs)) {
		INFO("validator: failed to load SGT\n");
		return PVAL_ESGT;
	}

	INFO("validator: validate_and_activate_strict: loaded SGT count=%lu\n",
	     (unsigned long)loaded_sgt.count);

	for (uint16_t i = 0; i < self_cfg->num_mems && i < PARSER_MAX_MEMS; i++) {
		const struct parsed_mem *m = &self_cfg->mems[i];

		INFO("validator: scan mem[%u] '%c%c%c%c' type=%u size=0x%llx maps=%u\n",
		     i, m->name[0], m->name[1], m->name[2], m->name[3],
		     m->type,
		     (unsigned long long)m->size,
		     m->num_mappings);

		if (m->type != MEM_PROTECTED)
			continue;

		int rc = validate_and_activate_mem_strict(self_cfg, self_pd_addr,
							 &loaded_sgt, m->name);
		if (rc != PVAL_OK) {
			INFO("validator: protected mem '%c%c%c%c' failed rc=%d\n",
			     m->name[0], m->name[1], m->name[2], m->name[3], rc);
			return rc;
		}
	}

	INFO("validator: validate_and_activate_strict: OK\n");
	return PVAL_OK;
}

static int validate_and_activate(struct parsed_payload *self_cfg,
                                 unsigned long self_pd_addr)
{
	INFO("validator: validate_and_activate: begin self_pd=0x%lx num_mems=%u\n",
	     self_pd_addr, self_cfg->num_mems);

	if (!sgt_load_into_and_dump(&loaded_sgt, loaded_sgt_addrs)) {
		INFO("validator: failed to load SGT\n");
		return PVAL_ESGT;
	}

	INFO("validator: validate_and_activate: loaded SGT count=%lu\n",
	     (unsigned long)loaded_sgt.count);

	for (uint16_t i = 0; i < self_cfg->num_mems && i < PARSER_MAX_MEMS; i++) {
		const struct parsed_mem *m = &self_cfg->mems[i];

		INFO("validator: scan mem[%u] '%c%c%c%c' type=%u size=0x%llx maps=%u\n",
		     i, m->name[0], m->name[1], m->name[2], m->name[3],
		     m->type,
		     (unsigned long long)m->size,
		     m->num_mappings);

		if (m->type != MEM_PROTECTED)
			continue;

		int rc = validate_and_activate_mem(self_cfg, self_pd_addr,
		                                   &loaded_sgt, m->name);
		if (rc != PVAL_OK) {
			INFO("validator: protected mem '%c%c%c%c' failed rc=%d\n",
			     m->name[0], m->name[1], m->name[2], m->name[3], rc);
			return rc;
		}
	}

	INFO("validator: validate_and_activate: OK\n");
	return PVAL_OK;
}

int validate_and_activate_all_protected(struct parsed_payload *self_cfg,
                                        unsigned long self_pd_addr)
{
	if (!self_cfg) {
		INFO("validator: validate_and_activate_all_protected: self_cfg=NULL\n");
		return PVAL_EARGS;
	}

	INFO("validator: validate_and_activate_all_protected: begin self_pd=0x%lx\n",
	     self_pd_addr);

	/* Branch based on strict flag of self VM */
	bool self_is_strict = self_cfg->vms[self_cfg->self_vm_index].strict;

	if (self_is_strict) {
		return validate_and_activate_strict(self_cfg, self_pd_addr);
	} else {
		return validate_and_activate(self_cfg, self_pd_addr);
	}
}
