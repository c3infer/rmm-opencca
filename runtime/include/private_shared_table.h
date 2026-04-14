#ifndef PRIVATE_SHARED_TABLE_H
#define PRIVATE_SHARED_TABLE_H


#include <spinlock.h>
#include <debug.h>

#define MAX_PST_ENTRIES 32
#define MAX_PAS_PER_RD  8

typedef spinlock_t pst_lock_t;
extern pst_lock_t pstlock;
void init_pst_lock_init(void);

typedef struct {
    unsigned long rd_addr;                    /* owning RD granule */
    unsigned long ipa;
    unsigned long size;
    unsigned long pas[MAX_PAS_PER_RD];     /* data PAs */
    unsigned int pa_count;
} pst_entry_t;

typedef struct {
    unsigned int count;
    pst_entry_t e[MAX_PST_ENTRIES];
} pst_t;

extern pst_t pst;

int pst_add_tuple(unsigned long rd_addr,
                    unsigned long ipa,
                    unsigned long size);

int pst_add_pa(unsigned long rd_addr,
                unsigned long ipa,
                unsigned long pa);

unsigned long pst_get_rd_from_pa(unsigned long pa);

int pst_get_rd_pa_from_ipa(unsigned long ipa,
                            unsigned long *out_rd,
                            unsigned long *out_pa);
unsigned int pst_remove_entries_from_rd(unsigned long rd_addr);
unsigned int pst_scrub_stale_entries(void);
void pst_pretty_print(void);

#endif
