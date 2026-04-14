#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "policy_parser.h"
#include "debug.h"

/* Forward declare functions from policy_validator.c */
int validate_and_activate_all_protected(struct parsed_payload *self_cfg,
                                        unsigned long self_pd_addr);

/* Stubs for external ram/table functions used by policy_validator.c */

/* Simple deterministic mapping: rd = hash + 100; pd = rd + 1000 */
int ram_get_entry_from_hash(uint32_t hash, type_rim_t *out)
{
    if (!out) return 0;
    out->rd_addr = (unsigned long)(hash + 100);
    out->pd_addr = (unsigned long)(out->rd_addr + 1000);
    return 1;
}

int ram_get_entry_from_rd(unsigned long rd, type_rim_t *out)
{
    if (!out) return 0;
    out->rd_addr = rd;
    out->pd_addr = rd + 1000;
    return 1;
}

/* load_cfg/upload_cfg not used in our tests because peers are skipped; provide trivial stubs */
int load_cfg(unsigned long pd, struct parsed_payload *out, int a, int b)
{
    (void)pd; (void)out; (void)a; (void)b; return 0; /* not loading peers */
}

int upload_cfg(unsigned long pd, struct parsed_payload *cfg, int a, int b)
{
    (void)pd; (void)cfg; (void)a; (void)b; return 1; /* pretend success */
}

/* Control variable to pick SGT content per test case */
static int test_case = 0;

int sgt_load_into_and_dump(struct sgt *sgt, unsigned long *addrs)
{
    if (!sgt) return 0;
    sgt->count = 0;

    if (test_case == 0) {
        /* Non-strict success: single page at base_gpa=0x1000 with rd = self_rd */
        sgt->entries[0].gpa = 0x1000ULL;
        sgt->entries[0].pa  = 0x2000UL;
        /* rd for self hash 42 -> 42 + 100 */
        sgt->entries[0].rd  = (unsigned long)(42 + 100);
        sgt->count = 1;
    } else if (test_case == 1) {
        /* Strict failure: object has two mappings (self at 0x1000, peer at 0x2000).
         * SGT contains entry at 0x2000 with rd == self_rd -> illegal.
         */
        sgt->entries[0].gpa = 0x1000ULL; sgt->entries[0].pa = 0x2000UL; sgt->entries[0].rd = (unsigned long)(99 + 100);
        sgt->entries[1].gpa = 0x2000ULL; sgt->entries[1].pa = 0x3000UL; sgt->entries[1].rd = (unsigned long)(42 + 100); /* self_rd */
        sgt->count = 2;
    } else if (test_case == 2) {
        /* Strict success: same as case0 but for strict path (self mapping only) */
        sgt->entries[0].gpa = 0x1000ULL; sgt->entries[0].pa = 0x2000UL; sgt->entries[0].rd = (unsigned long)(42 + 100);
        sgt->count = 1;
    }

    (void)addrs;
    return 1;
}

/* Test 1: validate_and_activate (non-strict) should succeed */
int test_validate_and_activate(void)
{
    struct parsed_payload cfg;
    memset(&cfg, 0, sizeof(cfg));

    cfg.num_mems = 1;
    cfg.num_vms = 1;
    cfg.num_cfs = 0;
    cfg.self_vm_index = 0;
    cfg.vms[0].hash = 42;
    cfg.vms[0].is_gateway = 0;
    cfg.vms[0].strict = 0;
    cfg.vms[0].name[0] = 'A';

    cfg.mems[0].name[0] = 'M'; cfg.mems[0].type = MEM_PROTECTED; cfg.mems[0].status = 0;
    cfg.mems[0].size = GRANULE_SIZE; cfg.mems[0].num_mappings = 1;
    cfg.mems[0].mappings[0].vm_index = 0;
    cfg.mems[0].mappings[0].gpa = 0x1000ULL;
    cfg.mems[0].mappings[0].prot = 0;

    /* compute self_pd_addr matching our ram stubs */
    unsigned long self_rd = (unsigned long)(cfg.vms[0].hash + 100);
    unsigned long self_pd = self_rd + 1000;

    test_case = 0;
    int rc = validate_and_activate_all_protected(&cfg, self_pd);
    if (rc != PVAL_OK) {
        printf("test_validate_and_activate: FAILED rc=%d\n", rc);
        return 1;
    }
    printf("test_validate_and_activate: PASS\n");
    return 0;
}

/* Test 2: validate_and_activate_strict should fail due to extra self mapping in SGT */
int test_validate_and_activate_strict_fail(void)
{
    struct parsed_payload cfg;
    memset(&cfg, 0, sizeof(cfg));

    cfg.num_mems = 1;
    cfg.num_vms = 2;
    cfg.num_cfs = 0;
    cfg.self_vm_index = 0;
    cfg.vms[0].hash = 42; cfg.vms[0].strict = 1; cfg.vms[0].name[0] = 'A';
    cfg.vms[1].hash = 99; cfg.vms[1].strict = 0; cfg.vms[1].name[0] = 'B';

    cfg.mems[0].name[0] = 'M'; cfg.mems[0].type = MEM_PROTECTED; cfg.mems[0].status = 0;
    cfg.mems[0].size = GRANULE_SIZE; cfg.mems[0].num_mappings = 2;
    cfg.mems[0].mappings[0].vm_index = 0; cfg.mems[0].mappings[0].gpa = 0x1000ULL;
    cfg.mems[0].mappings[1].vm_index = 1; cfg.mems[0].mappings[1].gpa = 0x2000ULL;

    unsigned long self_rd = (unsigned long)(cfg.vms[0].hash + 100);
    unsigned long self_pd = self_rd + 1000;

    test_case = 1; /* sgt will include entry at 0x2000 with rd == self_rd */
    int rc = validate_and_activate_all_protected(&cfg, self_pd);
    if (rc != PVAL_ESGT_RD_ILLEGAL) {
        printf("test_validate_and_activate_strict_fail: FAILED rc=%d (expected %d)\n", rc, PVAL_ESGT_RD_ILLEGAL);
        return 1;
    }
    printf("test_validate_and_activate_strict_fail: PASS\n");
    return 0;
}

/* Test 3: validate_and_activate_strict success */
int test_validate_and_activate_strict_success(void)
{
    struct parsed_payload cfg;
    memset(&cfg, 0, sizeof(cfg));

    cfg.num_mems = 1;
    cfg.num_vms = 1;
    cfg.num_cfs = 0;
    cfg.self_vm_index = 0;
    cfg.vms[0].hash = 42; cfg.vms[0].strict = 1; cfg.vms[0].name[0] = 'A';

    cfg.mems[0].name[0] = 'M'; cfg.mems[0].type = MEM_PROTECTED; cfg.mems[0].status = 0;
    cfg.mems[0].size = GRANULE_SIZE; cfg.mems[0].num_mappings = 1;
    cfg.mems[0].mappings[0].vm_index = 0; cfg.mems[0].mappings[0].gpa = 0x1000ULL;

    unsigned long self_rd = (unsigned long)(cfg.vms[0].hash + 100);
    unsigned long self_pd = self_rd + 1000;

    test_case = 2;
    int rc = validate_and_activate_all_protected(&cfg, self_pd);
    if (rc != PVAL_OK) {
        printf("test_validate_and_activate_strict_success: FAILED rc=%d\n", rc);
        return 1;
    }
    printf("test_validate_and_activate_strict_success: PASS\n");
    return 0;
}

int main(void)
{
    int fail = 0;
    fail |= test_validate_and_activate();
    fail |= test_validate_and_activate_strict_fail();
    fail |= test_validate_and_activate_strict_success();
    return fail;
}
