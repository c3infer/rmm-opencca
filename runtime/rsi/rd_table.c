#include <rd_table.h>
#include <string.h> /* for memset if needed */

rd_lock_t rdlock;
rd_table_t rdtab = { .count = 0 };

static inline void rd_lock_init(rd_lock_t *l)
{
    l->val = 0U;
}

static inline void rd_lock(rd_lock_t *l)
{
    spinlock_acquire(l);
}

static inline void rd_unlock(rd_lock_t *l)
{
    spinlock_release(l);
}

void init_rd_lock_init(void)
{
    rd_lock_init(&rdlock);
}

/* add or update */
int rdtab_add(unsigned long rd_addr)
{
    unsigned int i;

    rd_lock(&rdlock);

    /* update if exists */
    for (i = 0; i < rdtab.count; i++) {
        if (rdtab.e[i].rd_addr == rd_addr) {
            rd_unlock(&rdlock);
            return 1;
        }
    }

    /* add new */
    if (rdtab.count >= MAX_RD_ENTRIES) {
        rd_unlock(&rdlock);
        return 0; /* table full */
    }

    rdtab.e[rdtab.count].rd_addr = rd_addr;
    rdtab.count++;

    rd_unlock(&rdlock);
    return 1;
}

unsigned int rdtab_get_all(rd_entry_t *out, unsigned int max_out)
{
    unsigned int i, n;

    rd_lock(&rdlock);

    n = rdtab.count;
    if (n > max_out)
        n = max_out;

    for (i = 0; i < n; i++) {
        out[i] = rdtab.e[i];
    }

    rd_unlock(&rdlock);
    return n;
}

void rdtab_pretty_print(void)
{
    unsigned int i;

    rd_lock(&rdlock);

    INFO("RD table: count=%u\n", rdtab.count);
    for (i = 0; i < rdtab.count; i++) {
        INFO("  [%2u] rd_addr=0x%lx\n",
             i,
             rdtab.e[i].rd_addr);
    }

    rd_unlock(&rdlock);
}
