#include <private_shared_table.h>
#include <granule.h>
#include <string.h>

pst_lock_t pstlock;
pst_t pst = {.count = 0};

static inline void pst_lock_init(pst_lock_t *l) {
    /* .bss will zero g_rim_set_lock, but make init explicit for safety */
    l->val = 0U;
}

static inline void pst_lock(pst_lock_t *l) {
    spinlock_acquire(l);
}

static inline void pst_unlock(pst_lock_t *l) {
    spinlock_release(l);
}

void init_pst_lock_init(void) {
    /* .bss will zero g_rim_set_lock, but make init explicit for safety */
    pst_lock_init(&pstlock);
}

/* create (or no-op if exists) a <rd, ipa, size> tuple */
int pst_add_tuple(unsigned long rd_addr,
                                unsigned long ipa,
                                unsigned long size)
{
    int ret = 0;

    pst_lock(&pstlock);

    /* already present? */
    for (unsigned int i = 0; i < pst.count; i++) {
        if (pst.e[i].rd_addr == rd_addr &&
            pst.e[i].ipa == ipa &&
            pst.e[i].size == size)
            goto out; /* no-op */
    }

    if (pst.count >= MAX_PST_ENTRIES) {
        ret = -1;
        goto out;
    }

    pst_entry_t *p = &pst.e[pst.count++];
    p->rd_addr  = rd_addr;
    p->ipa      = ipa;
    p->size     = size;
    p->pa_count = 0;

out:
    pst_unlock(&pstlock);
    return ret;
}

/* append a PA to an existing <rd, ipa, size> tuple */
int pst_add_pa(unsigned long rd_addr,
                             unsigned long ipa,
                             unsigned long pa)
{
    int ret = -1; /* default: tuple not found */

    pst_lock(&pstlock);

    for (unsigned int i = 0; i < pst.count; i++) {
        pst_entry_t *p = &pst.e[i];
        if (p->rd_addr == rd_addr && ipa >= p->ipa && ipa + 0x1000 <= p->ipa + p->size) {
            /* found tuple */
            ret = 0;

            /* already present? */
            for (unsigned int j = 0; j < p->pa_count; j++)
                if (p->pas[j] == pa)
                    goto out;

            if (p->pa_count >= MAX_PAS_PER_RD) {
                ret = -1;
                goto out;
            }

            p->pas[p->pa_count++] = pa;
            goto out;
        }
    }

out:
    pst_unlock(&pstlock);
    return ret;
}

/* Lookup helper: RD from PA */
unsigned long pst_get_rd_from_pa(unsigned long pa)
{
    unsigned long rd_addr = 0;

    pst_lock(&pstlock);
    for (unsigned int i = 0; i < pst.count; i++) {
        for (unsigned int j = 0; j < pst.e[i].pa_count; j++) {
            if (pst.e[i].pas[j] == pa) {
                rd_addr = pst.e[i].rd_addr;
                goto out;
            }
        }
    }
out:
    pst_unlock(&pstlock);
    return rd_addr;
}

int pst_get_rd_pa_from_ipa(unsigned long ipa,
                            unsigned long *out_rd,
                            unsigned long *out_pa)
{
    int ret = -1;

    pst_lock(&pstlock);

    for (unsigned int i = 0; i < pst.count; i++) {
        pst_entry_t *p = &pst.e[i];
        if (p->ipa == ipa && p->pa_count) {
            if (out_rd) *out_rd = p->rd_addr;
            if (out_pa && p->pas[0]) *out_pa = p->pas[0]; /* first PA we recorded - need to make this more flexible*/
            ret = 0;
            goto out;
        }
    }
out:
    pst_unlock(&pstlock);
    return ret;
}

unsigned int pst_remove_entries_from_rd(unsigned long rd_addr)
{
    unsigned int i = 0U;
    unsigned int removed = 0U;

    pst_lock(&pstlock);

    while (i < pst.count) {
        if (pst.e[i].rd_addr != rd_addr) {
            i++;
            continue;
        }

        removed++;
        if (i != (pst.count - 1U)) {
            pst.e[i] = pst.e[pst.count - 1U];
        }
        memset(&pst.e[pst.count - 1U], 0, sizeof(pst.e[pst.count - 1U]));
        pst.count--;
    }

    pst_unlock(&pstlock);
    return removed;
}

unsigned int pst_scrub_stale_entries(void)
{
    unsigned int i = 0U;
    unsigned int removed = 0U;

    pst_lock(&pstlock);

    while (i < pst.count) {
        struct granule *g_rd = find_granule(pst.e[i].rd_addr);

        if ((g_rd != NULL) &&
            (granule_unlocked_state(g_rd) == GRANULE_STATE_RD)) {
            i++;
            continue;
        }

        removed++;
        if (i != (pst.count - 1U)) {
            pst.e[i] = pst.e[pst.count - 1U];
        }
        memset(&pst.e[pst.count - 1U], 0, sizeof(pst.e[pst.count - 1U]));
        pst.count--;
    }

    pst_unlock(&pstlock);
    return removed;
}

/* pretty-print the PST contents (compact) */
void pst_pretty_print(void)
{
    pst_lock(&pstlock);

    INFO("PST: %u entr%s\n", pst.count, pst.count == 1 ? "y" : "ies");

    for (unsigned int i = 0; i < pst.count; i++) {
        pst_entry_t *p = &pst.e[i];

        INFO("[%u] RD=0x%lx IPA=[0x%lx..0x%lx) sz=0x%lx PAs(%u):",
             i, p->rd_addr, p->ipa, p->ipa + p->size, p->size, p->pa_count);

        for (unsigned int j = 0; j < p->pa_count; j++)
            INFO(" 0x%lx", p->pas[j]);

        INFO("\n");
    }

    pst_unlock(&pstlock);
}
