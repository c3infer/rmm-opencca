#ifndef PSR_HPA_OWNER_TABLE_H
#define PSR_HPA_OWNER_TABLE_H

#include <spinlock.h>
#include <debug.h>
#include <stdint.h>
#include <granule.h>

/* One entry per 4KB granule/page */
#define PSR_PAGE_MASK (~(GRANULE_SIZE - 1UL))

/* 64 MiB * 8 = 512 MiB -> 512 MiB / 4 KiB = 131072 pages */
#define MAX_PSR_HPA_ENTRIES 131072

typedef spinlock_t psr_hpa_lock_t;
extern psr_hpa_lock_t psr_hpa_lock;
void psr_hpa_lock_init(void);

typedef uint16_t psr_id_t;

typedef struct {
    unsigned long hpa_page; /* key: 4KB-aligned HPA */
    psr_id_t psr_id;        /* owning PSR */
    uint8_t used;           /* 0=empty, 1=used */
} psr_hpa_entry_t;

typedef struct {
    unsigned int count;
    psr_hpa_entry_t e[MAX_PSR_HPA_ENTRIES];
} psr_hpa_tbl_t;

extern psr_hpa_tbl_t psr_hpa_tbl;

/* Claim ownership of one 4KB HPA page for psr_id.
 * - If already claimed by same psr_id: no-op (success)
 * - If claimed by different psr_id: conflict (fail)
 * Returns 0 on success, -1 on conflict or table full.
 */
int psr_hpa_claim(psr_id_t psr_id, unsigned long hpa);

/* Release ownership of one 4KB HPA page for psr_id.
 * - If not present: no-op (success)
 * - If present but owned by different psr_id: conflict (fail)
 * Returns 0 on success, -1 on conflict.
 */
int psr_hpa_release(psr_id_t psr_id, unsigned long hpa);

/* Lookup owner PSR for an HPA page.
 * Returns 0 if found (and writes *out_psr_id), -1 if not found.
 */
int psr_hpa_get_owner(unsigned long hpa, psr_id_t *out_psr_id);

/* Debug */
void psr_hpa_pretty_print(void);

#endif /* PSR_HPA_OWNER_TABLE_H */
