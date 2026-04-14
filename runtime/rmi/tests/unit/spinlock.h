#ifndef SPINLOCK_TEST_H
#define SPINLOCK_TEST_H

#include <stdint.h>

typedef struct { unsigned int val; } spinlock_t;

/* Provide prototypes; implementations live in spinlock.c for the unit test.
 * This avoids duplicate definitions when the header is included into the
 * test compilation unit that also links the implementation file.
 */
void spinlock_acquire(spinlock_t *l);
void spinlock_release(spinlock_t *l);

#endif
