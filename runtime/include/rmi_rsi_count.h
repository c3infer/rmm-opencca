#ifndef RMI_RSI_COUNT_H
#define RMI_RSI_COUNT_H


#include <spinlock.h>
#include <debug.h>

typedef spinlock_t rrt_lock_t;
extern rrt_lock_t rrtlock;
void init_rrt_lock_init(void);

typedef struct {
    unsigned int rmi;
    unsigned int rsi;
} rmi_rsi_t;

extern rmi_rsi_t rrt;

void rmi_plus_one();

void rsi_plus_one();

void rrt_pretty_print(void);

#endif