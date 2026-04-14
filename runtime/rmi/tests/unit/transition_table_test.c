#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "transition_table.h"

static void reset_table(void) {
    transitiontable.count = 0;
}

int main(void) {
    int rc;
    reset_table();

    /* 1) Add non-strict entry */
    rc = transition_table_add(1, 1, 100, 7, false, NULL, 0);
    if (rc != 0) { printf("FAIL: initial add returned %d\n", rc); return 1; }

    /* 2) Add duplicate non-strict entry (should be no-op) */
    rc = transition_table_add(1, 1, 100, 7, false, NULL, 0);
    if (rc != 0) { printf("FAIL: duplicate non-strict add returned %d\n", rc); return 1; }

    /* 3) Add strict entry with peers (should succeed and populate peers) */
    uint32_t peers1[] = { 0xdeadbeef, 0xcafebabe };
    rc = transition_table_add(1, 1, 100, 7, true, peers1, 2);
    if (rc != 0) { printf("FAIL: strict add after non-strict returned %d\n", rc); return 1; }

    /* 4) Add non-strict same tuple (should still succeed) */
    rc = transition_table_add(1, 1, 100, 7, false, NULL, 0);
    if (rc != 0) { printf("FAIL: non-strict add after strict returned %d\n", rc); return 1; }

    /* 5) Add strict with different peer set (should conflict -> return -3) */
    uint32_t peers2[] = { 0xfeedface, 0xabad1dea };
    rc = transition_table_add(1, 1, 100, 7, true, peers2, 2);
    if (rc != -3) { printf("FAIL: strict add with different peers returned %d (expected -3)\n", rc); return 1; }

    printf("PASS\n");
    return 0;
}
