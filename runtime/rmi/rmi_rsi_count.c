#include <rmi_rsi_count.h>

rrt_lock_t rrtlock;
rmi_rsi_t rrt = {.rmi = 0, .rsi = 0};

static inline void rrt_lock_init(rrt_lock_t *l) {
    /* .bss will zero g_rim_set_lock, but make init explicit for safety */
    l->val = 0U;
}

static inline void rrt_lock(rrt_lock_t *l) {
    spinlock_acquire(l);
}

static inline void rrt_unlock(rrt_lock_t *l) {
    spinlock_release(l);
}

void init_rrt_lock_init(void) {
    /* .bss will zero g_rim_set_lock, but make init explicit for safety */
    rrt_lock_init(&rrtlock);
}

void rmi_plus_one(){
    rrt_lock(&rrtlock);
    rrt.rmi = rrt.rmi + 1;
    rrt_unlock(&rrtlock);
}

void rsi_plus_one(){
    rrt_lock(&rrtlock);
    rrt.rsi = rrt.rsi + 1;
    rrt_unlock(&rrtlock);
}

void rrt_pretty_print(void)
{
    rrt_lock(&rrtlock);
    INFO("RMI: %u RSI: %u\n", rrt.rmi, rrt.rsi);
    rrt_unlock(&rrtlock);
}
