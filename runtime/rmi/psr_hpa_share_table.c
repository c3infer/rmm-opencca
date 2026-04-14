#include "psr_hpa_share_table.h"

psr_hpa_lock_t psr_hpa_lock;
psr_hpa_tbl_t psr_hpa_tbl = { .count = 0 };

static inline unsigned long align_down_4k(unsigned long x)
{
    return x & PSR_PAGE_MASK;
}

static inline void lock_init(psr_hpa_lock_t *l)
{
    /* .bss will zero it, but keep explicit init for safety */
    l->val = 0U;
}

static inline void lock(psr_hpa_lock_t *l)
{
    spinlock_acquire(l);
}

static inline void unlock(psr_hpa_lock_t *l)
{
    spinlock_release(l);
}

void psr_hpa_lock_init(void)
{
    lock_init(&psr_hpa_lock);
}

/* Linear search; simplest. */
static int find_idx(unsigned long hpa_page)
{
    for (unsigned int i = 0; i < psr_hpa_tbl.count; i++) {
        if (psr_hpa_tbl.e[i].used && psr_hpa_tbl.e[i].hpa_page == hpa_page)
            return (int)i;
    }
    return -1;
}

int psr_hpa_claim(psr_id_t psr_id, unsigned long hpa)
{
    int ret = 0;
    unsigned long hpa_page = align_down_4k(hpa);

    lock(&psr_hpa_lock);

    int idx = find_idx(hpa_page);
    if (idx >= 0) {
        /* already claimed: must be by the same PSR */
        if (psr_hpa_tbl.e[idx].psr_id != psr_id) {
            ERROR("PSR_HPA: CONFLICT claim HPA=0x%lx owned_by_psr=%u new_psr=%u\n",
                  hpa_page, (unsigned)psr_hpa_tbl.e[idx].psr_id, (unsigned)psr_id);
            ret = -1;
        }
        goto out;
    }

    if (psr_hpa_tbl.count >= MAX_PSR_HPA_ENTRIES) {
        ERROR("PSR_HPA: TABLE FULL max=%u\n", (unsigned)MAX_PSR_HPA_ENTRIES);
        ret = -1;
        goto out;
    }

    psr_hpa_entry_t *p = &psr_hpa_tbl.e[psr_hpa_tbl.count++];
    p->used = 1;
    p->hpa_page = hpa_page;
    p->psr_id = psr_id;

out:
    unlock(&psr_hpa_lock);
    return ret;
}

int psr_hpa_release(psr_id_t psr_id, unsigned long hpa)
{
    int ret = 0;
    unsigned long hpa_page = align_down_4k(hpa);

    lock(&psr_hpa_lock);

    int idx = find_idx(hpa_page);
    if (idx < 0)
        goto out; /* idempotent */

    psr_hpa_entry_t *p = &psr_hpa_tbl.e[idx];

    if (p->psr_id != psr_id) {
        ERROR("PSR_HPA: CONFLICT release HPA=0x%lx owned_by_psr=%u req_psr=%u\n",
              hpa_page, (unsigned)p->psr_id, (unsigned)psr_id);
        ret = -1;
        goto out;
    }

    /* swap-remove */
    unsigned int last = psr_hpa_tbl.count - 1U;
    if ((unsigned)idx != last)
        psr_hpa_tbl.e[idx] = psr_hpa_tbl.e[last];

    psr_hpa_tbl.e[last].used = 0;
    psr_hpa_tbl.e[last].hpa_page = 0;
    psr_hpa_tbl.e[last].psr_id = 0;
    psr_hpa_tbl.count--;

out:
    unlock(&psr_hpa_lock);
    return ret;
}

int psr_hpa_get_owner(unsigned long hpa, psr_id_t *out_psr_id)
{
    int ret = -1;
    unsigned long hpa_page = align_down_4k(hpa);

    lock(&psr_hpa_lock);

    int idx = find_idx(hpa_page);
    if (idx >= 0) {
        if (out_psr_id)
            *out_psr_id = psr_hpa_tbl.e[idx].psr_id;
        ret = 0;
    }

    unlock(&psr_hpa_lock);
    return ret;
}

void psr_hpa_pretty_print(void)
{
    lock(&psr_hpa_lock);

    INFO("PSR_HPA_TBL: %u entr%s\n",
         psr_hpa_tbl.count, psr_hpa_tbl.count == 1 ? "y" : "ies");

    for (unsigned int i = 0; i < psr_hpa_tbl.count; i++) {
        psr_hpa_entry_t *p = &psr_hpa_tbl.e[i];
        INFO("[%u] HPA=0x%lx PSR=%u\n", i, p->hpa_page, (unsigned)p->psr_id);
    }

    unlock(&psr_hpa_lock);
}
