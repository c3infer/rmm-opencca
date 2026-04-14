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

    /* Prepare two tuples */
    uint16_t owners[] = { 1, 2 };
    uint16_t types[] = { 1, 1 };
    uint32_t ranges[] = { 100, 200 };

    /* Add both as non-strict entries */
    rc = transition_table_add(1, 1, 100, 7, false, NULL, 0);
    if (rc != 0) { printf("FAIL: add1 returned %d\n", rc); return 1; }
    rc = transition_table_add(2, 1, 200, 3, false, NULL, 0);
    if (rc != 0) { printf("FAIL: add2 returned %d\n", rc); return 1; }

    /* Now strict-check: ensure strict check fails if CF list doesn't cover non-strict entries */
    rc = transition_table_strict_check_no_conflicts(owners, types, ranges, 1); /* only first tuple provided */
    if (rc != -1) { printf("FAIL: strict_check should have failed (-1) but returned %d\n", rc); return 1; }

    /* Now provide full list and expect success */
    rc = transition_table_strict_check_no_conflicts(owners, types, ranges, 2);
    if (rc != 0) { printf("FAIL: strict_check should have succeeded but returned %d\n", rc); return 1; }

    /* Mark first tuple strict */
    rc = transition_table_mark_entries_strict(&owners[0], &types[0], &ranges[0], 1);
    if (rc != 0) { printf("FAIL: mark_entries_strict returned %d\n", rc); return 1; }

    /* Now check has_strict_entries */
    if (!transition_table_has_strict_entries()) { printf("FAIL: has_strict_entries should be 1\n"); return 1; }

    printf("PASS\n");
    return 0;
}
