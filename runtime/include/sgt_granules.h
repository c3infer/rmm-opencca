#ifndef SGT_GRANULES_H
#define SGT_GRANULES_H


#include <spinlock.h>
#include <debug.h>

#define MAX_SGT_GRANULES_ENTRIES 32

typedef spinlock_t sgt_granules_lock_t;
extern sgt_granules_lock_t sgtgranuleslock;
void init_sgt_granules_lock_init(void);

typedef struct {
    unsigned int count;
    unsigned long addr[MAX_SGT_GRANULES_ENTRIES];
} sgt_granules_t;

extern sgt_granules_t sgtgranules;

int sgt_granules_add_pa(unsigned long sgt_addr);

void sgt_granules_get_all(unsigned long addrs[MAX_SGT_GRANULES_ENTRIES]);
unsigned int sgt_granules_get_all_counted(unsigned long addrs[MAX_SGT_GRANULES_ENTRIES]);
bool sgt_granules_all_released_to_host(void);
unsigned int sgt_granules_prune_released_to_host(void);
void sgt_granules_reset(void);

void sgt_granules_pretty_print(void);

#endif
