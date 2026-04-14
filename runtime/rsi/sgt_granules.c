#include <sgt_granules.h>
#include <granule.h>
#include <string.h>

sgt_granules_lock_t sgtgranuleslock;
sgt_granules_t sgtgranules = {.count = 0};

static void sgt_granules_sort_locked(void)
{
    for (unsigned int i = 1U; i < sgtgranules.count; i++) {
        unsigned long key = sgtgranules.addr[i];
        unsigned int j = i;

        while ((j > 0U) && (sgtgranules.addr[j - 1U] > key)) {
            sgtgranules.addr[j] = sgtgranules.addr[j - 1U];
            j--;
        }
        sgtgranules.addr[j] = key;
    }
}

static inline void sgt_granules_lock_init(sgt_granules_lock_t *l) {
    /* .bss will zero g_rim_set_lock, but make init explicit for safety */
    l->val = 0U;
}

static inline void sgt_granules_lock(sgt_granules_lock_t *l) {
    spinlock_acquire(l);
}

static inline void sgt_granules_unlock(sgt_granules_lock_t *l) {
    spinlock_release(l);
}

void init_sgt_granules_lock_init(void) {
    /* .bss will zero g_rim_set_lock, but make init explicit for safety */
    sgt_granules_lock_init(&sgtgranuleslock);
}

/* create (or no-op if exists) a <rd, ipa, size> tuple */
int sgt_granules_add_pa(unsigned long sgt_addr)
{
    int ret = 0;

    sgt_granules_lock(&sgtgranuleslock);

    /* already present? */
    for (unsigned int i = 0; i < sgtgranules.count; i++) {
        if (sgtgranules.addr[i] == sgt_addr)
            goto out; /* no-op */
    }

    if (sgtgranules.count >= MAX_SGT_GRANULES_ENTRIES) {
        ret = -1;
        goto out;
    }

    sgtgranules.addr[sgtgranules.count++] = sgt_addr;
    sgt_granules_sort_locked();

out:
    sgt_granules_unlock(&sgtgranuleslock);
    return ret;
}

void sgt_granules_get_all(unsigned long addrs[MAX_SGT_GRANULES_ENTRIES]){
    if (!addrs) {
        return;
    }

    sgt_granules_lock(&sgtgranuleslock);
    memset(addrs, 0, sizeof(unsigned long) * MAX_SGT_GRANULES_ENTRIES);
    for (unsigned int i = 0; i < sgtgranules.count; i++) {
        addrs[i] = sgtgranules.addr[i];
    }
    sgt_granules_unlock(&sgtgranuleslock);
}

unsigned int sgt_granules_get_all_counted(unsigned long addrs[MAX_SGT_GRANULES_ENTRIES])
{
    unsigned int count;

    if (!addrs) {
        return 0U;
    }

    sgt_granules_lock(&sgtgranuleslock);

    count = sgtgranules.count;
    memset(addrs, 0, sizeof(unsigned long) * MAX_SGT_GRANULES_ENTRIES);
    for (unsigned int i = 0; i < sgtgranules.count; i++) {
        addrs[i] = sgtgranules.addr[i];
    }

    sgt_granules_unlock(&sgtgranuleslock);

    return count;
}

bool sgt_granules_all_released_to_host(void)
{
    bool released = true;

    sgt_granules_lock(&sgtgranuleslock);
    for (unsigned int i = 0; i < sgtgranules.count; i++) {
        unsigned long pa = sgtgranules.addr[i];
        struct granule *g;

        if (pa == 0UL) {
            continue;
        }

        g = find_granule(pa);
        if ((g != NULL) &&
            (granule_unlocked_state(g) == GRANULE_STATE_DELEGATED)) {
            released = false;
            break;
        }
    }
    sgt_granules_unlock(&sgtgranuleslock);

    return released;
}

unsigned int sgt_granules_prune_released_to_host(void)
{
    unsigned int w = 0U;
    unsigned int removed = 0U;

    sgt_granules_lock(&sgtgranuleslock);
    for (unsigned int i = 0U; i < sgtgranules.count; i++) {
        unsigned long pa = sgtgranules.addr[i];
        struct granule *g = NULL;
        bool keep = true;

        if (pa != 0UL) {
            g = find_granule(pa);
        }

        if ((g == NULL) || (granule_unlocked_state(g) != GRANULE_STATE_DELEGATED)) {
            keep = false;
        }

        if (keep) {
            sgtgranules.addr[w++] = pa;
            continue;
        }

        removed++;
    }
    for (unsigned int i = w; i < sgtgranules.count; i++) {
        sgtgranules.addr[i] = 0UL;
    }
    sgtgranules.count = w;
    sgt_granules_sort_locked();
    sgt_granules_unlock(&sgtgranuleslock);

    return removed;
}

void sgt_granules_reset(void)
{
    sgt_granules_lock(&sgtgranuleslock);
    memset(sgtgranules.addr, 0, sizeof(sgtgranules.addr));
    sgtgranules.count = 0U;
    sgt_granules_unlock(&sgtgranuleslock);
}

/* pretty-print the SGT granules contents (compact) */
void sgt_granules_pretty_print(void)
{
    sgt_granules_lock(&sgtgranuleslock);

    INFO("SGT granules: %u entr%s\n", sgtgranules.count, sgtgranules.count == 1 ? "y" : "ies");

    for (unsigned int i = 0; i < sgtgranules.count; i++) {
        INFO("SGT PA[%i]: [%lu] \n", i, sgtgranules.addr[i]);
    }

    sgt_granules_unlock(&sgtgranuleslock);
}
