#ifndef SGT_H
#define SGT_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include <debug.h>          /* INFO/WARN */
#include <sgt_granules.h>   /* sgt_granules_get_all, MAX_SGT_GRANULES_ENTRIES */

/* RMM granule APIs (as used in your example) */
#include <granule.h>
#include <buffer.h>

#ifndef SGT_MAX_ENTRIES
#define SGT_MAX_ENTRIES 4096u
#endif

struct sgt_entry {
	unsigned long pa;
	unsigned long gpa;
	unsigned long rd;
};

struct sgt {
	size_t count;
	struct sgt_entry entries[SGT_MAX_ENTRIES];
};

static inline void sgt_init(struct sgt *t)
{
	if (t) {
		t->count = 0;
	}
}

/* Add or update (pa,rd)->gpa. Returns 0 on success, <0 on overflow/args. */
int sgt_upsert(struct sgt *t,
               unsigned long pa,
               unsigned long gpa,
               unsigned long rd);

/* Remove mapping for (pa,rd). Returns true if removed. */
bool sgt_remove(struct sgt *t,
                unsigned long pa,
                unsigned long rd);

/* Lookup gpa for (pa,rd). Returns true if found. */
bool sgt_lookup(const struct sgt *t,
                unsigned long pa,
                unsigned long rd,
                unsigned long *out_gpa);

/* Count distinct RDs mapping a PA (optionally copy them). */
size_t sgt_distinct_rds_for_pa(const struct sgt *t,
                               unsigned long pa,
                               unsigned long *out_rds,
                               size_t max_out);

/* Print all entries (PA,GPA,RD). */
void sgt_dump(const struct sgt *t);

/* -------------------------------------------------------------------------- */
/* Persist SGT into delegated granules                                        */
/* -------------------------------------------------------------------------- */

/*
 * Binary layout stored in granules:
 *   u32 magic
 *   u32 version
 *   u32 count
 *   u32 reserved
 *   followed by count * entry records:
 *     u64 pa
 *     u64 gpa
 *     u64 rd
 *
 * Stored little-endian.
 */
#define SGT_BLOB_MAGIC   0x53475442u /* 'SGTB' */
#define SGT_BLOB_VERSION 1u

/*
 * Serialize the SGT and write it into delegated granules.
 *
 * - addrs[] must contain delegated granule PAs; caller typically obtains them via:
 *       unsigned long addrs[MAX_SGT_GRANULES_ENTRIES];
 *       sgt_granules_get_all(addrs);
 *
 * Returns true on success, false on any mapping/locking/size failure.
 */
bool sgt_store_to_granules(const unsigned long addrs[MAX_SGT_GRANULES_ENTRIES],
                           const struct sgt *t);

/*
 * Read SGT blob from granules and deserialize into *out.
 *
 * Returns true on success, false on bad magic/version/size or mapping failure.
 */
bool sgt_load_from_granules(const unsigned long addrs[MAX_SGT_GRANULES_ENTRIES],
                            struct sgt *out);

/*
 * Zero the delegated granules used for SGT storage.
 * This is the simplest "wipe/unmap backing store" operation.
 */
bool sgt_clear_granules(const unsigned long addrs[MAX_SGT_GRANULES_ENTRIES]);

/* Load SGT from delegated granules into caller-provided *out.
 * Optionally returns the granule address list used in out_addrs (may be NULL).
 */
bool sgt_load_into(struct sgt *out,
                   unsigned long out_addrs[MAX_SGT_GRANULES_ENTRIES]);

/* Convenience: load + dump into caller-provided *out (no persistent global). */
bool sgt_load_into_and_dump(struct sgt *out,
                            unsigned long out_addrs[MAX_SGT_GRANULES_ENTRIES]);

bool sgt_load_add_store(unsigned long pa, unsigned long gpa, unsigned long rd);

bool sgt_load_add_dump_store(unsigned long pa, unsigned long gpa, unsigned long rd);

#endif /* SGT_H */
