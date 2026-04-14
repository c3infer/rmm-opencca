#include <policy_parser.h>

static inline bool config_is_nonempty(const struct parsed_payload *p)
{
	return p && p->num_vms != 0 && p->num_mems != 0;
}

static uint16_t rd_u16(const uint8_t *p)
{
	return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t rd_u32(const uint8_t *p)
{
	return (uint32_t)p[0] |
	       ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

static uint64_t rd_u64(const uint8_t *p)
{
	return (uint64_t)p[0]        |
	       ((uint64_t)p[1] << 8) |
	       ((uint64_t)p[2] << 16)|
	       ((uint64_t)p[3] << 24)|
	       ((uint64_t)p[4] << 32)|
	       ((uint64_t)p[5] << 40)|
	       ((uint64_t)p[6] << 48)|
	       ((uint64_t)p[7] << 56);
}

static int32_t rd_i32(const uint8_t *p)
{
	return (int32_t)rd_u32(p);
}

int parse_payload(const uint8_t *buf, size_t len, struct parsed_payload *out)
{
	const uint8_t *p = buf;
	size_t remain = len;

	if (!buf || !out)
		return -1;

	memset(out, 0, sizeof(*out));

	/* ---- Header ---- */
	if (remain < 16)
		return -2;

	uint32_t magic         = rd_u32(p + 0);
	uint16_t version       = rd_u16(p + 4);
	uint16_t self_vm_index = rd_u16(p + 6);
	uint16_t num_vms       = rd_u16(p + 8);
	uint16_t num_mems      = rd_u16(p + 10);
	uint16_t num_cfs       = rd_u16(p + 12);
	/* u16 reserved at +14 */

	p      += 16;
	remain -= 16;

	if (magic != PAYLOAD_MAGIC)
		return -3;
	if (version != 1)
		return -4;

	out->self_vm_index = self_vm_index;
	out->num_vms  = (num_vms  > PARSER_MAX_VMS)  ? PARSER_MAX_VMS  : num_vms;
	out->num_mems = (num_mems > PARSER_MAX_MEMS) ? PARSER_MAX_MEMS : num_mems;
	out->num_cfs  = (num_cfs  > PARSER_MAX_CFS)  ? PARSER_MAX_CFS  : num_cfs;

	/* ---- VM section ---- */
	const size_t VM_REC_SIZE = 12;

	if (remain < (size_t)num_vms * VM_REC_SIZE)
		return -5;

	for (uint16_t i = 0; i < num_vms; i++) {
		const uint8_t *vp = p + (size_t)i * VM_REC_SIZE;

		if (i < PARSER_MAX_VMS) {
			memcpy(out->vms[i].name, vp + 0, 4);
			out->vms[i].hash       = rd_u32(vp + 4);
			out->vms[i].is_gateway = vp[8] ? 1 : 0;
			out->vms[i].strict     = vp[9] ? 1 : 0;
		}
	}

	p      += (size_t)num_vms * VM_REC_SIZE;
	remain -= (size_t)num_vms * VM_REC_SIZE;

	if (num_vms > out->num_vms) {
		WARN("Policy: %u VMs, stored %u\n", num_vms, out->num_vms);
	}
	if (self_vm_index != 0xFFFFu && self_vm_index >= num_vms) {
		return -6;
	}

	/* ---- MEM section ---- */
	for (uint16_t mi = 0; mi < num_mems; mi++) {
		/* MEM_HDR */
		if (remain < 16)
			return -7;

		char     name_tmp[4];
		uint64_t size_tmp = rd_u64(p + 4);
		uint16_t type_tmp = rd_u16(p + 12);
		uint16_t maps_tmp = rd_u16(p + 14);

		memcpy(name_tmp, p + 0, 4);

		p      += 16;
		remain -= 16;

		if (type_tmp != MEM_PROTECTED && type_tmp != MEM_UNPROTECTED)
			return -8;

		/* MAP section */
		const size_t MAP_REC_SIZE = 20;
		if (remain < (size_t)maps_tmp * MAP_REC_SIZE)
			return -9;

		int store_mem = (mi < PARSER_MAX_MEMS) ? 1 : 0;
		struct parsed_mem *pmem = NULL;
		if (store_mem) {
			pmem = &out->mems[mi];
			memset(pmem, 0, sizeof(*pmem));
			memcpy(pmem->name, name_tmp, 4);
			pmem->size = size_tmp;
			pmem->type = type_tmp;
			pmem->num_mappings = (maps_tmp > PARSER_MAX_MAPS) ? PARSER_MAX_MAPS : maps_tmp;
		}

		/* Parse each mapping record */
		for (uint16_t mj = 0; mj < maps_tmp; mj++) {
			const uint8_t *mp = p + (size_t)mj * MAP_REC_SIZE;

			uint16_t vm_index  = rd_u16(mp + 0);
			uint16_t prot      = rd_u16(mp + 2);
			uint64_t gpa_base  = rd_u64(mp + 4);
			int32_t  any_count = rd_i32(mp + 12);
			/* u32 reserved at +16 */

			/* vm_index: allow ANY (0xFFFF) else must be < num_vms */
			if (vm_index != VM_IDX_ANY && vm_index >= num_vms)
				return -10;

			/* prot stored; enforce basic validity */
			if (prot != PROT_R && prot != PROT_W && prot != PROT_RW)
				return -11;

			/* ANY must have a count (>= -1). We treat < -1 as invalid. */
			if (vm_index == VM_IDX_ANY) {
				if (any_count < -1)
					return -12;
			} else {
				/* non-ANY: require any_count == 0 (or ignore; choose strictness) */
				/* If you prefer to tolerate garbage, comment this out. */
				if (any_count != 0)
					return -13;
			}

			if (store_mem && mj < PARSER_MAX_MAPS) {
				struct parsed_mapping *m = &pmem->mappings[mj];
				m->vm_index   = vm_index;
				m->prot       = prot;
				m->gpa        = gpa_base;
				m->any_count  = any_count;
			}
		}

		p      += (size_t)maps_tmp * MAP_REC_SIZE;
		remain -= (size_t)maps_tmp * MAP_REC_SIZE;

		if (store_mem && maps_tmp > PARSER_MAX_MAPS) {
			WARN("Policy: MEM '%c%c%c%c' has %u mappings, stored %u\n",
			     name_tmp[0], name_tmp[1], name_tmp[2], name_tmp[3],
			     maps_tmp, pmem->num_mappings);
		}
	}

	if (num_mems > out->num_mems) {
		WARN("Policy: %u MEMs, stored %u\n", num_mems, out->num_mems);
	}

	/* ---- CF section ---- */
	for (uint16_t ci = 0; ci < num_cfs; ci++) {
		if (remain < 12)
			return -14;

		char     name_tmp[4];
		uint16_t owner_tmp = rd_u16(p + 4);
		uint16_t type_tmp  = rd_u16(p + 6);
		uint16_t pol_tmp   = rd_u16(p + 8);
		uint16_t rlen_tmp  = rd_u16(p + 10);

		memcpy(name_tmp, p + 0, 4);

		p      += 12;
		remain -= 12;

		if (owner_tmp != 0xFFFFu && owner_tmp >= num_vms)
			return -15;

		/* type/policy enums are stored; be permissive if you want */
		if (type_tmp == 0) type_tmp = CF_TYPE_OTHER;
		if (pol_tmp  == 0) pol_tmp  = CF_POLICY_OTHER;

		/* range */
		if (remain < (size_t)rlen_tmp * 4u)
			return -16;

		int store_cf = (ci < PARSER_MAX_CFS) ? 1 : 0;
		struct parsed_cf *pcf = NULL;
		if (store_cf) {
			pcf = &out->cfs[ci];
			memset(pcf, 0, sizeof(*pcf));
			memcpy(pcf->name, name_tmp, 4);
			pcf->owner_vm_index = owner_tmp;
			pcf->type = type_tmp;
			pcf->policy = pol_tmp;
			pcf->range_len = (rlen_tmp > PARSER_MAX_CF_RANGE) ? PARSER_MAX_CF_RANGE : rlen_tmp;
		}

		for (uint16_t ri = 0; ri < rlen_tmp; ri++) {
			uint32_t v = rd_u32(p + (size_t)ri * 4u);
			if (store_cf && ri < PARSER_MAX_CF_RANGE) {
				pcf->range[ri] = v;
			}
		}

		p      += (size_t)rlen_tmp * 4u;
		remain -= (size_t)rlen_tmp * 4u;

		if (store_cf && rlen_tmp > PARSER_MAX_CF_RANGE) {
			WARN("Policy: CF '%c%c%c%c' has %u range elems, stored %u\n",
			     name_tmp[0], name_tmp[1], name_tmp[2], name_tmp[3],
			     rlen_tmp, pcf->range_len);
		}
	}

	if (num_cfs > out->num_cfs) {
		WARN("Policy: %u CFs, stored %u\n", num_cfs, out->num_cfs);
	}

	return 0;
}

bool load_cfg(unsigned long pd_addr, struct parsed_payload *cfg0, char expected_state, enum buffer_slot slot)
{
    struct granule *gr = find_lock_granule(pd_addr, expected_state);
    if (!gr) {
        INFO("load_cfg: failed to lock PD granule at 0x%lx\n", pd_addr);
        return false;
    }

    uint8_t *pd_phys = buffer_granule_map(gr, slot);
    if (!pd_phys) {
        INFO("load_cfg: buffer_granule_map failed (slot=%u)\n", (unsigned)slot);
        granule_unlock(gr);
        return false;
    }

    memcpy(cfg0, pd_phys, sizeof(*cfg0));

    buffer_unmap(pd_phys);
    granule_unlock(gr);

    if (!config_is_nonempty(cfg0))
        return false;

    return true;
}

bool upload_cfg(unsigned long pd_addr, const struct parsed_payload *cfg0, char expected_state, enum buffer_slot slot)
{
    struct granule *gr = find_lock_granule(pd_addr, expected_state);
    if (!gr) {
        INFO("upload_cfg: failed to lock PD granule at 0x%lx\n", pd_addr);
        return false;
    }

    uint8_t *pd_phys = buffer_granule_map(gr, slot);
    if (!pd_phys) {
        INFO("upload_cfg: buffer_granule_map failed (slot=%u)\n", (unsigned)slot);
        granule_unlock(gr);
        return false;
    }

    memcpy(pd_phys, cfg0, sizeof(*cfg0));   /* FIXED */

    buffer_unmap(pd_phys);
    granule_unlock(gr);

    if (!config_is_nonempty(cfg0))
        return false;

    return true;
}

/* Policy dump */
static inline const char *prot_s(uint16_t p)
{
	switch (p) {
	case PROT_R:  return "R";
	case PROT_W:  return "W";
	case PROT_RW: return "RW";
	default:      return "?";
	}
}

static inline const char *mem_type_s(uint16_t t)
{
	switch (t) {
	case MEM_PROTECTED:   return "PROT";
	case MEM_UNPROTECTED: return "UNPROT";
	case MEM_OTHER:       return "OTHER";
	default:              return "?";
	}
}

static inline const char *cf_type_s(uint16_t t)
{
	switch (t) {
	case CF_TYPE_CALL:       return "CALL";
	case CF_TYPE_EXCEPTION:  return "EXCEP";
	case CF_TYPE_OTHER:      return "OTHER";
	default:                 return "?";
	}
}

static inline const char *cf_policy_s(uint16_t p)
{
	switch (p) {
	case CF_POLICY_BLOCK: return "BLOCK";
	case CF_POLICY_ALLOW: return "ALLOW";
	case CF_POLICY_OTHER: return "OTHER";
	default:              return "?";
	}
}

void dump_parsed_payload(const struct parsed_payload *cfg)
{
	if (!cfg) {
		INFO("POLICY: <null>\n");
		return;
	}

	/* Self */
	if (cfg->self_vm_index != 0xFFFF && cfg->self_vm_index < cfg->num_vms) {
		const struct parsed_vm *self = &cfg->vms[cfg->self_vm_index];
		INFO("POLICY: self='%c%c%c%c' (idx=%u)\n",
		     self->name[0], self->name[1], self->name[2], self->name[3],
		     (unsigned)cfg->self_vm_index);
	} else {
		INFO("POLICY: self=<none> (idx=0x%04x)\n", cfg->self_vm_index);
	}

	/* VMs */
	INFO("POLICY: VMs=%u\n", (unsigned)cfg->num_vms);
	for (uint16_t i = 0; i < cfg->num_vms; i++) {
		const struct parsed_vm *v = &cfg->vms[i];
		INFO("  VM[%u] '%c%c%c%c' hash=0x%08x gw=%u strict=%u\n",
		     (unsigned)i,
		     v->name[0], v->name[1], v->name[2], v->name[3],
		     v->hash,
		     (unsigned)v->is_gateway,
		     (unsigned)v->strict);
	}

	/* MEMs */
	INFO("POLICY: MEMs=%u\n", (unsigned)cfg->num_mems);
	for (uint16_t mi = 0; mi < cfg->num_mems; mi++) {
		const struct parsed_mem *m = &cfg->mems[mi];
		INFO("  MEM[%u] '%c%c%c%c' size=0x%llx type=%s maps=%u\n",
				(unsigned)mi,
				m->name[0], m->name[1], m->name[2], m->name[3],
				(unsigned long long)m->size,
				mem_type_s(m->type),
				(unsigned)m->num_mappings);

		for (uint16_t k = 0; k < m->num_mappings; k++) {
			const struct parsed_mapping *mp = &m->mappings[k];

			if (mp->vm_index == VM_IDX_ANY) {
				INFO("    MAP[%u] vm=ANY gpa=0x%llx prot=%s any_count=%ld\n",
					(unsigned)k,
					(unsigned long long)mp->gpa,
					prot_s(mp->prot),
					(long)mp->any_count);
			} else if (mp->vm_index < cfg->num_vms) {
				const struct parsed_vm *v = &cfg->vms[mp->vm_index];
				INFO("    MAP[%u] vm=%u('%c%c%c%c') gpa=0x%llx prot=%s\n",
					(unsigned)k,
					(unsigned)mp->vm_index,
					v->name[0], v->name[1], v->name[2], v->name[3],
					(unsigned long long)mp->gpa,
					prot_s(mp->prot));
			} else {
				INFO("    MAP[%u] vm=%u(<bad>) gpa=0x%llx prot=%s\n",
				     (unsigned)k,
				     (unsigned)mp->vm_index,
				     (unsigned long long)mp->gpa,
				     prot_s(mp->prot));
			}
		}
	}

	/* CFs */
	INFO("POLICY: CFs=%u\n", (unsigned)cfg->num_cfs);
	for (uint16_t ci = 0; ci < cfg->num_cfs; ci++) {
		const struct parsed_cf *c = &cfg->cfs[ci];

		const char *owner_s = "<none>";
		char owner_name[5] = {0};

		if (c->owner_vm_index != 0xFFFF && c->owner_vm_index < cfg->num_vms) {
			const struct parsed_vm *v = &cfg->vms[c->owner_vm_index];
			owner_name[0] = v->name[0];
			owner_name[1] = v->name[1];
			owner_name[2] = v->name[2];
			owner_name[3] = v->name[3];
			owner_s = owner_name;
		}

		INFO("  CF[%u] '%c%c%c%c' owner=%s(0x%04x) type=%s policy=%s range_len=%u\n",
		     (unsigned)ci,
		     c->name[0], c->name[1], c->name[2], c->name[3],
		     owner_s, c->owner_vm_index,
		     cf_type_s(c->type),
		     cf_policy_s(c->policy),
		     (unsigned)c->range_len);

		for (uint16_t r = 0; r < c->range_len && r < PARSER_MAX_CF_RANGE; r++) {
			INFO("    RANGE[%u]=0x%08x\n",
			     (unsigned)r,
			     c->range[r]);
		}
	}
}
