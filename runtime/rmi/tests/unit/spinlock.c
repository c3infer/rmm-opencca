#include "spinlock.h"

void spinlock_acquire_impl(spinlock_t *l) { (void)l; }
void spinlock_release_impl(spinlock_t *l) { (void)l; }

/* expose weak symbols matching project's expected names if needed */
void spinlock_acquire(spinlock_t *l) { (void)l; }
void spinlock_release(spinlock_t *l) { (void)l; }
