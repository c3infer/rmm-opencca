#ifndef RD_TABLE_H
#define RD_TABLE_H

#include <spinlock.h>
#include <debug.h>

#define MAX_RD_ENTRIES 32

typedef spinlock_t rd_lock_t;
extern rd_lock_t rdlock;
void init_rd_lock_init(void);

typedef struct {
    unsigned long rd_addr;  /* PA of the RD granule */
} rd_entry_t;

typedef struct {
    unsigned int count;
    rd_entry_t e[MAX_RD_ENTRIES];
} rd_table_t;

extern rd_table_t rdtab;

/* add or update an RD entry; returns 1 on success, 0 on full */
int rdtab_add(unsigned long rd_addr);

/* get all RDs: copies current entries into out[], returns number copied */
unsigned int rdtab_get_all(rd_entry_t *out, unsigned int max_out);

/* print all */
void rdtab_pretty_print(void);

#endif /* RD_TABLE_H */
