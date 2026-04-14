#include "sgt.h"
#include <sgt_granules.h>
#include <string.h>

/* -------------------- SGT in-RAM operations -------------------- */

int sgt_upsert(struct sgt *t,
               unsigned long pa,
               unsigned long gpa,
               unsigned long rd)
{
	if (!t || pa == 0ul || rd == 0ul) {
		return -1;
	}

	/* Update existing (pa,rd) */
	for (size_t i = 0; i < t->count; i++) {
		if (t->entries[i].pa == pa && t->entries[i].rd == rd) {
			t->entries[i].gpa = gpa;
			return 0;
		}
	}

	/* Insert new */
	if (t->count >= SGT_MAX_ENTRIES) {
		return -2;
	}

	t->entries[t->count].pa  = pa;
	t->entries[t->count].gpa = gpa;
	t->entries[t->count].rd  = rd;
	t->count++;
	return 0;
}

bool sgt_remove(struct sgt *t, unsigned long pa, unsigned long rd)
{
	if (!t) return false;

	for (size_t i = 0; i < t->count; i++) {
		if (t->entries[i].pa == pa && t->entries[i].rd == rd) {
			/* swap-remove */
			t->entries[i] = t->entries[t->count - 1];
			t->count--;
			return true;
		}
	}
	return false;
}

bool sgt_lookup(const struct sgt *t,
                unsigned long pa,
                unsigned long rd,
                unsigned long *out_gpa)
{
	if (!t || !out_gpa) return false;

	for (size_t i = 0; i < t->count; i++) {
		if (t->entries[i].pa == pa && t->entries[i].rd == rd) {
			*out_gpa = t->entries[i].gpa;
			return true;
		}
	}
	return false;
}

static bool rd_in_list(unsigned long rd, const unsigned long *rds, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		if (rds[i] == rd) return true;
	}
	return false;
}

size_t sgt_distinct_rds_for_pa(const struct sgt *t,
                               unsigned long pa,
                               unsigned long *out_rds,
                               size_t max_out)
{
	size_t n = 0;

	if (!t) return 0;

	for (size_t i = 0; i < t->count; i++) {
		if (t->entries[i].pa != pa) continue;

		if (out_rds && n < max_out) {
			if (!rd_in_list(t->entries[i].rd, out_rds, n)) {
				out_rds[n++] = t->entries[i].rd;
			}
		} else if (!out_rds) {
			/* count-only distinct (O(n^2), fine for small counts per PA) */
			bool seen = false;
			for (size_t j = 0; j < i; j++) {
				if (t->entries[j].pa == pa &&
				    t->entries[j].rd == t->entries[i].rd) {
					seen = true;
					break;
				}
			}
			if (!seen) n++;
		}
	}

	/* If capped output array provided, compute true distinct total. */
	if (out_rds && n == max_out) {
		size_t total = 0;
		for (size_t i = 0; i < t->count; i++) {
			if (t->entries[i].pa != pa) continue;
			bool seen = false;
			for (size_t j = 0; j < i; j++) {
				if (t->entries[j].pa == pa &&
				    t->entries[j].rd == t->entries[i].rd) {
					seen = true;
					break;
				}
			}
			if (!seen) total++;
		}
		return total;
	}

	return n;
}

void sgt_dump(const struct sgt *t)
{
	if (!t) {
		INFO("SGT: <null>\n");
		return;
	}

	INFO("SGT: %zu entries\n", t->count);
	for (size_t i = 0; i < t->count; i++) {
		const struct sgt_entry *e = &t->entries[i];
		INFO("  [%zu] PA=0x%lx GPA=0x%lx RD=0x%lx\n",
		     i, e->pa, e->gpa, e->rd);
	}
}

/* -------------------- Little-endian helpers -------------------- */

static inline void wr_u32_le(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v);
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static inline void wr_u64_le(uint8_t *p, uint64_t v)
{
	p[0] = (uint8_t)(v);
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
	p[4] = (uint8_t)(v >> 32);
	p[5] = (uint8_t)(v >> 40);
	p[6] = (uint8_t)(v >> 48);
	p[7] = (uint8_t)(v >> 56);
}

static inline uint32_t rd_u32_le(const uint8_t *p)
{
	return (uint32_t)p[0] |
	       ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

static inline uint64_t rd_u64_le(const uint8_t *p)
{
	return (uint64_t)p[0] |
	       ((uint64_t)p[1] << 8) |
	       ((uint64_t)p[2] << 16) |
	       ((uint64_t)p[3] << 24) |
	       ((uint64_t)p[4] << 32) |
	       ((uint64_t)p[5] << 40) |
	       ((uint64_t)p[6] << 48) |
	       ((uint64_t)p[7] << 56);
}

/* -------------------- Granule sequential I/O -------------------- */

struct sgt_seqio {
	const unsigned long *addrs;
	size_t off; /* current offset from start of blob */
};

static int sgt_entry_cmp(const struct sgt_entry *a, const struct sgt_entry *b)
{
	if (a->rd < b->rd) {
		return -1;
	}
	if (a->rd > b->rd) {
		return 1;
	}
	if (a->gpa < b->gpa) {
		return -1;
	}
	if (a->gpa > b->gpa) {
		return 1;
	}
	if (a->pa < b->pa) {
		return -1;
	}
	if (a->pa > b->pa) {
		return 1;
	}
	return 0;
}

static bool sgt_seq_write(struct sgt_seqio *io, const uint8_t *src, size_t n)
{
    size_t left = n;

    if (!io || !io->addrs || (!src && n)) {
        INFO("SGT: seq_write invalid args io=%p addrs=%p src=%p n=%zu\n",
              io, io ? io->addrs : NULL, src, n);
        return false;
    }

    // INFO("SGT: seq_write begin off=%zu n=%zu\n", io->off, n);

    while (left > 0) {
        unsigned idx = (unsigned)(io->off / GRANULE_SIZE);
        size_t in_gr_off = io->off % GRANULE_SIZE;

        if (idx >= MAX_SGT_GRANULES_ENTRIES) {
            INFO("SGT: seq_write OOB idx=%u off=%zu max=%u\n",
                 idx, io->off, (unsigned)MAX_SGT_GRANULES_ENTRIES);
            return false;
        }

        unsigned long pa = io->addrs[idx];
        if (pa == 0ul) {
            INFO("SGT: seq_write missing pa idx=%u off=%zu\n", idx, io->off);
            return false;
        }

        size_t space = GRANULE_SIZE - in_gr_off;
        size_t chunk = (left < space) ? left : space;

        // INFO("SGT: seq_write idx=%u pa=0x%lx off=%zu in_off=%zu chunk=%zu\n",
        //       idx, pa, io->off, in_gr_off, chunk);

        struct granule *gr = find_lock_granule(pa, GRANULE_STATE_DELEGATED);
        if (!gr) {
            INFO("SGT: seq_write find_lock_granule failed pa=0x%lx idx=%u\n", pa, idx);
            return false;
        }

        uint8_t *dst = buffer_granule_map(gr, SLOT_DELEGATED);
        if (!dst) {
            INFO("SGT: seq_write map failed pa=0x%lx idx=%u\n", pa, idx);
            granule_unlock(gr);
            return false;
        }

        memcpy(dst + in_gr_off, src, chunk);

        buffer_unmap(dst);
        granule_unlock(gr);

        io->off += chunk;
        src     += chunk;
        left    -= chunk;
    }

    // INFO("SGT: seq_write end off=%zu\n", io->off);
    return true;
}

static bool sgt_seq_read(struct sgt_seqio *io, uint8_t *dst, size_t n)
{
    size_t left = n;

    if (!io || !io->addrs || (!dst && n)) {
        INFO("SGT: seq_read invalid args io=%p addrs=%p dst=%p n=%zu\n",
              io, io ? io->addrs : NULL, dst, n);
        return false;
    }

    // INFO("SGT: seq_read begin off=%zu n=%zu\n", io->off, n);

    while (left > 0) {
        unsigned idx = (unsigned)(io->off / GRANULE_SIZE);
        size_t in_gr_off = io->off % GRANULE_SIZE;

        if (idx >= MAX_SGT_GRANULES_ENTRIES) {
            INFO("SGT: seq_read OOB idx=%u off=%zu max=%u\n",
                 idx, io->off, (unsigned)MAX_SGT_GRANULES_ENTRIES);
            return false;
        }

        unsigned long pa = io->addrs[idx];
        if (pa == 0ul) {
            INFO("SGT: seq_read missing pa idx=%u off=%zu\n", idx, io->off);
            return false;
        }

        size_t avail = GRANULE_SIZE - in_gr_off;
        size_t chunk = (left < avail) ? left : avail;

        // INFO("SGT: seq_read idx=%u pa=0x%lx off=%zu in_off=%zu chunk=%zu\n",
        //       idx, pa, io->off, in_gr_off, chunk);

        struct granule *gr = find_lock_granule(pa, GRANULE_STATE_DELEGATED);
        if (!gr) {
            INFO("SGT: seq_read find_lock_granule failed pa=0x%lx idx=%u\n", pa, idx);
            return false;
        }

        uint8_t *src = buffer_granule_map(gr, SLOT_DELEGATED);
        if (!src) {
            INFO("SGT: seq_read map failed pa=0x%lx idx=%u\n", pa, idx);
            granule_unlock(gr);
            return false;
        }

        memcpy(dst, src + in_gr_off, chunk);

        buffer_unmap(src);
        granule_unlock(gr);

        io->off += chunk;
        dst     += chunk;
        left    -= chunk;
    }

    // INFO("SGT: seq_read end off=%zu\n", io->off);
    return true;
}


/* -------------------- Persist / load / clear -------------------- */

bool sgt_clear_granules(const unsigned long addrs[MAX_SGT_GRANULES_ENTRIES])
{
    if (!addrs) return false;

    for (unsigned i = 0; i < MAX_SGT_GRANULES_ENTRIES; i++) {
        unsigned long pa = addrs[i];
        if (pa == 0ul) {
            INFO("SGT: clear end-of-list at %u\n", i);
            return true;
        }

        // INFO("SGT: clear idx=%u pa=0x%lx\n", i, pa);

        struct granule *gr = find_lock_granule(pa, GRANULE_STATE_DELEGATED);
        if (!gr) {
            INFO("SGT: clear lock failed idx=%u pa=0x%lx\n", i, pa);
            return false;
        }

        uint8_t *dst = buffer_granule_map(gr, SLOT_DELEGATED);
        if (!dst) {
            INFO("SGT: clear map failed idx=%u pa=0x%lx\n", i, pa);
            granule_unlock(gr);
            return false;
        }

        memset(dst, 0, GRANULE_SIZE);

        buffer_unmap(dst);
        granule_unlock(gr);
    }

    return true;
}


bool sgt_store_to_granules(const unsigned long addrs[MAX_SGT_GRANULES_ENTRIES],
                           const struct sgt *t)
{
	uint32_t order[SGT_MAX_ENTRIES];

	if (!addrs || !t) return false;

	// INFO("SGT: store count=%zu MAX_ENTRIES=%u MAX_GR=%u GRANULE=%u cap=%zu\n",
	// 	t->count, (unsigned)SGT_MAX_ENTRIES,
	// 	(unsigned)MAX_SGT_GRANULES_ENTRIES, (unsigned)GRANULE_SIZE,
	// 	(size_t)MAX_SGT_GRANULES_ENTRIES * (size_t)GRANULE_SIZE);

    for (unsigned i = 0; i < MAX_SGT_GRANULES_ENTRIES; i++) {
        if (addrs[i] == 0ul) break;
        INFO("SGT: store addrs[%u]=0x%lx\n", i, addrs[i]);
    }

	if (t->count > SGT_MAX_ENTRIES) return false;

	size_t blob_len = 16u + (size_t)t->count * 24u;
	size_t cap = (size_t)MAX_SGT_GRANULES_ENTRIES * (size_t)GRANULE_SIZE;
	if (blob_len > cap) {
		INFO("SGT blob too large: %zu > %zu\n", blob_len, cap);
		return false;
	}

	uint8_t hdr[16];
	wr_u32_le(hdr + 0, SGT_BLOB_MAGIC);
	wr_u32_le(hdr + 4, SGT_BLOB_VERSION);
	wr_u32_le(hdr + 8, (uint32_t)t->count);
	wr_u32_le(hdr + 12, 0u);

	struct sgt_seqio io = { .addrs = addrs, .off = 0 };

	if (!sgt_seq_write(&io, hdr, sizeof(hdr))) {
		return false;
	}

	for (size_t i = 0; i < t->count; i++) {
		order[i] = (uint32_t)i;
	}
	/* Canonical ordering for stable cross-realm SGT view. */
	for (size_t i = 1; i < t->count; i++) {
		uint32_t key = order[i];
		size_t j = i;

		while ((j > 0U) &&
		       (sgt_entry_cmp(&t->entries[order[j - 1U]],
				      &t->entries[key]) > 0)) {
			order[j] = order[j - 1U];
			j--;
		}
		order[j] = key;
	}

	for (size_t i = 0; i < t->count; i++) {
		const struct sgt_entry *e = &t->entries[order[i]];
		uint8_t rec[24];
		wr_u64_le(rec + 0,  (uint64_t)e->pa);
		wr_u64_le(rec + 8,  (uint64_t)e->gpa);
		wr_u64_le(rec + 16, (uint64_t)e->rd);

		if (!sgt_seq_write(&io, rec, sizeof(rec))) {
			return false;
		}
	}

	return true;
}

bool sgt_load_from_granules(const unsigned long addrs[MAX_SGT_GRANULES_ENTRIES],
                            struct sgt *out)
{
	if (!addrs || !out) return false;

	// INFO("SGT: load MAX_GR=%u GRANULE=%u\n",
    //       (unsigned)MAX_SGT_GRANULES_ENTRIES, (unsigned)GRANULE_SIZE);

    for (unsigned i = 0; i < MAX_SGT_GRANULES_ENTRIES; i++) {
        if (addrs[i] == 0ul) break;
        // INFO("SGT: load addrs[%u]=0x%lx\n", i, addrs[i]);
    }

	memset(out, 0, sizeof(*out));

	struct sgt_seqio io = { .addrs = addrs, .off = 0 };

	uint8_t hdr[16];
	if (!sgt_seq_read(&io, hdr, sizeof(hdr))) {
		return false;
	}

	uint32_t magic   = rd_u32_le(hdr + 0);
	uint32_t version = rd_u32_le(hdr + 4);
	uint32_t count   = rd_u32_le(hdr + 8);

	if (magic != SGT_BLOB_MAGIC) return false;
	if (version != SGT_BLOB_VERSION) return false;
	if (count > SGT_MAX_ENTRIES) return false;

	size_t blob_len = 16u + (size_t)count * 24u;
	size_t cap = (size_t)MAX_SGT_GRANULES_ENTRIES * (size_t)GRANULE_SIZE;
	if (blob_len > cap) return false;

	out->count = (size_t)count;

	for (size_t i = 0; i < out->count; i++) {
		uint8_t rec[24];
		if (!sgt_seq_read(&io, rec, sizeof(rec))) {
			return false;
		}

		out->entries[i].pa  = (unsigned long)rd_u64_le(rec + 0);
		out->entries[i].gpa = (unsigned long)rd_u64_le(rec + 8);
		out->entries[i].rd  = (unsigned long)rd_u64_le(rec + 16);
	}

	return true;
}

bool sgt_load_into(struct sgt *out,
                   unsigned long out_addrs[MAX_SGT_GRANULES_ENTRIES])
{
	unsigned long addrs_local[MAX_SGT_GRANULES_ENTRIES];
	unsigned int pruned;

	if (!out)
		return false;

	/* Get delegated granules holding the SGT blob */
	sgt_granules_get_all(addrs_local);

	/* Optionally export the address list to caller */
	if (out_addrs) {
		memcpy(out_addrs, addrs_local, sizeof(addrs_local));
	}

	/* Load current SGT from delegated granules */
	if (!sgt_load_from_granules(addrs_local, out)) {
		INFO("SGT: load failed (blob missing/corrupt?). Trying prune+retry.\n");
		pruned = sgt_granules_prune_released_to_host();
		if (pruned > 0U) {
			INFO("SGT: pruned %u released granule(s), retrying load.\n", pruned);
			sgt_granules_get_all(addrs_local);
			if (out_addrs) {
				memcpy(out_addrs, addrs_local, sizeof(addrs_local));
			}
		}
		if (!sgt_load_from_granules(addrs_local, out)) {
			INFO("SGT: load retry failed.\n");
			return false;
		}
	}

	return true;
}

bool sgt_load_into_and_dump(struct sgt *out,
                            unsigned long out_addrs[MAX_SGT_GRANULES_ENTRIES])
{
	if (!sgt_load_into(out, out_addrs))
		return false;

	sgt_dump(out);
	return true;
}

bool sgt_load_add_store(unsigned long pa,
                        unsigned long gpa,
                        unsigned long rd)
{
    static unsigned long addrs[MAX_SGT_GRANULES_ENTRIES];
    static struct sgt t;

    (void)sgt_granules_prune_released_to_host();
    sgt_granules_get_all(addrs);

    /* Load current SGT from delegated granules */
    if (!sgt_load_from_granules(addrs, &t)) {
        INFO("SGT: load failed (blob missing/corrupt?). Initialising empty SGT.\n");
		sgt_init(&t);
    }

    sgt_upsert(&t, pa, gpa, rd);

    /* Persist the updated SGT back to granules */
    if (!sgt_store_to_granules(addrs, &t)) {
        INFO("SGT: store failed\n");
        return false;
    }

    return true;
}

bool sgt_load_add_dump_store(unsigned long pa,
                             unsigned long gpa,
                             unsigned long rd)
{
    static unsigned long addrs[MAX_SGT_GRANULES_ENTRIES];
    static struct sgt t;

    // INFO("SGT: enter pa=0x%lx gpa=0x%lx rd=0x%lx\n", pa, gpa, rd);
    // INFO("SGT: sizeof(addrs)=%zu (MAX_GR=%u) sizeof(sgt)=%zu total_locals~=%zu\n",
    //       sizeof(addrs), (unsigned)MAX_SGT_GRANULES_ENTRIES,
    //       sizeof(t), sizeof(addrs) + sizeof(t));

    (void)sgt_granules_prune_released_to_host();
    sgt_granules_get_all(addrs);

    // for (unsigned i = 0; i < MAX_SGT_GRANULES_ENTRIES; i++) {
    //     if (addrs[i] == 0ul) { INFO("SGT: addrs end at %u\n", i); break; }
    //     INFO("SGT: addrs[%u]=0x%lx\n", i, addrs[i]);
    // }

    /* Load current SGT from delegated granules */
    if (!sgt_load_from_granules(addrs, &t)) {
        INFO("SGT: load failed (blob missing/corrupt?). Initialising empty SGT.\n");
		sgt_init(&t);
    }

    sgt_upsert(&t, pa, gpa, rd);

    /* Print content */
    sgt_dump(&t);

    /* Optional but usually desired: persist the updated SGT back to granules */
    if (!sgt_store_to_granules(addrs, &t)) {
        INFO("SGT: store failed\n");
        return false;
    }

    return true;
}
