#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

/* Minimal stubs for policy_validator dependencies */
#define INFO(fmt, ...) printf(fmt "\n", ##__VA_ARGS__)
#define PVAL_OK 0
#define PVAL_EARGS -100
#define PVAL_ECFG_MISMATCH -101

#define PARSER_MAX_MEMS 4
#define PARSER_MAX_MAPS 4
#define PARSER_MAX_CFS 8
#define PARSER_MAX_CF_RANGE 16
#define PARSER_MAX_VMS 8
#define VM_IDX_ANY 0xFFFF

/* Minimal parsed structures */
struct parsed_cf {
	uint16_t owner_vm_index;
	uint16_t type;
	uint32_t range[PARSER_MAX_CF_RANGE];
	uint16_t range_len;
	uint16_t policy;
};

struct parsed_vm {
	uint32_t hash;
	char name[4];
	uint16_t is_gateway;
	uint16_t strict;
};

struct parsed_mem {
	char name[4];
	uint16_t type;
	uint16_t status;
	uint64_t size;
	uint16_t num_mappings;
};

struct parsed_payload {
	struct parsed_cf cfs[PARSER_MAX_CFS];
	uint16_t num_cfs;
	struct parsed_vm vms[PARSER_MAX_VMS];
	uint16_t num_vms;
	uint16_t self_vm_index;
	struct parsed_mem mems[PARSER_MAX_MEMS];
	uint16_t num_mems;
};

/* Transition table stubs for testing */
int transition_table_add(uint16_t owner, uint16_t type, uint32_t range, 
                        uint16_t policy, bool strict, 
                        const uint32_t *peer_hashes, uint16_t peer_count)
{
	INFO("  transition_table_add: owner=%u type=%u range=%u policy=%u strict=%d peer_count=%u",
	     owner, type, range, policy, strict, peer_count);
	return 0; /* Success */
}

int transition_table_strict_check_no_conflicts(const uint16_t *owners, 
                                               const uint16_t *types, 
                                               const uint32_t *ranges, 
                                               size_t count)
{
	INFO("  transition_table_strict_check_no_conflicts: count=%zu", count);
	return 0; /* No conflicts */
}

int transition_table_mark_entries_strict(const uint16_t *owners, 
                                         const uint16_t *types, 
                                         const uint32_t *ranges, 
                                         size_t count)
{
	INFO("  transition_table_mark_entries_strict: count=%zu", count);
	return 0; /* Success */
}

void transition_table_pretty_print(void)
{
	INFO("  [transition_table_pretty_print]");
}

/* Forward declare the functions we're testing (they're static in policy_validator.c) */
/* We'll need to extract and compile them separately or use a workaround */

/* For now, let's create inline versions to test the logic */
static int check_cf_compatibility_test(const struct parsed_payload *self_cfg,
                                       struct parsed_payload *peer_cfgs,
                                       size_t n_loaded)
{
	if (!self_cfg)
		return PVAL_EARGS;

	struct {
		uint16_t owner;
		uint16_t type;
		uint32_t range;
		uint16_t policy;
	} cfmap[(PARSER_MAX_MAPS + 1) * PARSER_MAX_CFS * PARSER_MAX_CF_RANGE];
	size_t cfmap_n = 0;

	/* Add self CFs first */
	for (size_t ci = 0; ci < (size_t)self_cfg->num_cfs; ci++) {
		const struct parsed_cf *cf = &self_cfg->cfs[ci];
		for (size_t ri = 0; ri < (size_t)cf->range_len; ri++) {
			uint32_t r = cf->range[ri];
			bool found = false;
			for (size_t k = 0; k < cfmap_n; k++) {
				if (cfmap[k].owner == cf->owner_vm_index && cfmap[k].type == cf->type && cfmap[k].range == r) {
					found = true;
					if (cfmap[k].policy != cf->policy) {
						INFO("CF policy conflict for owner=%u type=%u range=%u existing=%u self=%u\n",
							 (unsigned)cf->owner_vm_index, (unsigned)cf->type, (unsigned)r,
							 (unsigned)cfmap[k].policy, (unsigned)cf->policy);
						return PVAL_ECFG_MISMATCH;
					}
					break;
				}
			}
			if (!found) {
				if (cfmap_n >= (sizeof(cfmap)/sizeof(cfmap[0]))) {
					INFO("CF map overflow when adding self CF\n");
					return PVAL_ECFG_MISMATCH;
				}
				cfmap[cfmap_n].owner = cf->owner_vm_index;
				cfmap[cfmap_n].type = cf->type;
				cfmap[cfmap_n].range = r;
				cfmap[cfmap_n].policy = cf->policy;
				cfmap_n++;
			}
		}
	}

	/* Now iterate peers and check/add their CFs */
	for (size_t p = 0; p < n_loaded; p++) {
		const struct parsed_payload *pc = &peer_cfgs[p];
		for (size_t ci = 0; ci < (size_t)pc->num_cfs; ci++) {
			const struct parsed_cf *cf = &pc->cfs[ci];
			for (size_t ri = 0; ri < (size_t)cf->range_len; ri++) {
				uint32_t r = cf->range[ri];
				bool found = false;
				for (size_t k = 0; k < cfmap_n; k++) {
					if (cfmap[k].owner == cf->owner_vm_index && cfmap[k].type == cf->type && cfmap[k].range == r) {
						found = true;
						if (cfmap[k].policy != cf->policy) {
							INFO("CF policy conflict for owner=%u type=%u range=%u existing=%u peer=%u\n",
								 (unsigned)cf->owner_vm_index, (unsigned)cf->type, (unsigned)r,
								 (unsigned)cfmap[k].policy, (unsigned)cf->policy);
							return PVAL_ECFG_MISMATCH;
						}
						break;
					}
				}
				if (!found) {
					if (cfmap_n >= (sizeof(cfmap)/sizeof(cfmap[0]))) {
						INFO("CF map overflow when adding peer CF\n");
						return PVAL_ECFG_MISMATCH;
					}
					cfmap[cfmap_n].owner = cf->owner_vm_index;
					cfmap[cfmap_n].type = cf->type;
					cfmap[cfmap_n].range = r;
					cfmap[cfmap_n].policy = cf->policy;
					cfmap_n++;
				}
			}
		}
	}

	/* Record tuples in transition table (non-strict) */
	for (size_t k = 0; k < cfmap_n; k++) {
		int trc = transition_table_add(cfmap[k].owner, cfmap[k].type, cfmap[k].range, cfmap[k].policy, false, NULL, 0);
		if (trc != 0) {
			INFO("transition table add failed for tuple owner=%u type=%u range=%u\n",
			     (unsigned)cfmap[k].owner, (unsigned)cfmap[k].type, (unsigned)cfmap[k].range);
			return PVAL_ECFG_MISMATCH;
		}
	}
	transition_table_pretty_print();

	return PVAL_OK;
}

static int check_cf_compatibility_strict_test(const struct parsed_payload *self_cfg,
                                              struct parsed_payload *peer_cfgs,
                                              size_t n_loaded)
{
	if (!self_cfg)
		return PVAL_EARGS;

	struct {
		uint16_t owner;
		uint16_t type;
		uint32_t range;
		uint16_t policy;
	} cfmap[(PARSER_MAX_MAPS + 1) * PARSER_MAX_CFS * PARSER_MAX_CF_RANGE];
	size_t cfmap_n = 0;

	/* Collect CFs from self */
	for (size_t ci = 0; ci < (size_t)self_cfg->num_cfs; ci++) {
		const struct parsed_cf *cf = &self_cfg->cfs[ci];
		for (size_t ri = 0; ri < (size_t)cf->range_len; ri++) {
			uint32_t r = cf->range[ri];
			bool found = false;
			for (size_t k = 0; k < cfmap_n; k++) {
				if (cfmap[k].owner == cf->owner_vm_index && cfmap[k].type == cf->type && cfmap[k].range == r) {
					found = true;
					if (cfmap[k].policy != cf->policy) {
						INFO("strict CF policy conflict for owner=%u type=%u range=%u\n",
							 (unsigned)cf->owner_vm_index, (unsigned)cf->type, (unsigned)r);
						return PVAL_ECFG_MISMATCH;
					}
					break;
				}
			}
			if (!found) {
				if (cfmap_n >= (sizeof(cfmap)/sizeof(cfmap[0]))) {
					INFO("strict CF map overflow\n");
					return PVAL_ECFG_MISMATCH;
				}
				cfmap[cfmap_n].owner = cf->owner_vm_index;
				cfmap[cfmap_n].type = cf->type;
				cfmap[cfmap_n].range = r;
				cfmap[cfmap_n].policy = cf->policy;
				cfmap_n++;
			}
		}
	}

	/* Collect CFs from peers */
	for (size_t p = 0; p < n_loaded; p++) {
		const struct parsed_payload *pc = &peer_cfgs[p];
		for (size_t ci = 0; ci < (size_t)pc->num_cfs; ci++) {
			const struct parsed_cf *cf = &pc->cfs[ci];
			for (size_t ri = 0; ri < (size_t)cf->range_len; ri++) {
				uint32_t r = cf->range[ri];
				bool found = false;
				for (size_t k = 0; k < cfmap_n; k++) {
					if (cfmap[k].owner == cf->owner_vm_index && cfmap[k].type == cf->type && cfmap[k].range == r) {
						found = true;
						if (cfmap[k].policy != cf->policy) {
							INFO("strict CF policy conflict for peer CF\n");
							return PVAL_ECFG_MISMATCH;
						}
						break;
					}
				}
				if (!found) {
					if (cfmap_n >= (sizeof(cfmap)/sizeof(cfmap[0]))) {
						INFO("strict CF map overflow for peer\n");
						return PVAL_ECFG_MISMATCH;
					}
					cfmap[cfmap_n].owner = cf->owner_vm_index;
					cfmap[cfmap_n].type = cf->type;
					cfmap[cfmap_n].range = r;
					cfmap[cfmap_n].policy = cf->policy;
					cfmap_n++;
				}
			}
		}
	}

	/* Check strict table */
	{
		uint16_t owners[cfmap_n];
		uint16_t types[cfmap_n];
		uint32_t ranges[cfmap_n];
		for (size_t k = 0; k < cfmap_n; k++) {
			owners[k] = cfmap[k].owner;
			types[k] = cfmap[k].type;
			ranges[k] = cfmap[k].range;
		}
		int trc = transition_table_strict_check_no_conflicts(owners, types, ranges, cfmap_n);
		if (trc != 0) {
			INFO("strict mode: transition table conflict\n");
			return PVAL_ECFG_MISMATCH;
		}
	}

	/* Add tuples to transition table with peer hashes */
	uint32_t peer_hashes[PARSER_MAX_VMS];
	uint16_t peer_count = 0;
	for (uint16_t i = 0; i < self_cfg->num_vms && i < PARSER_MAX_VMS; i++) {
		if (i != self_cfg->self_vm_index) {
			peer_hashes[peer_count++] = self_cfg->vms[i].hash;
		}
	}

	for (size_t k = 0; k < cfmap_n; k++) {
		int trc = transition_table_add(cfmap[k].owner, cfmap[k].type, cfmap[k].range, cfmap[k].policy, false, peer_hashes, peer_count);
		if (trc != 0) {
			INFO("strict: transition table add failed\n");
			return PVAL_ECFG_MISMATCH;
		}
	}

	/* Mark entries as strict */
	{
		uint16_t owners[cfmap_n];
		uint16_t types[cfmap_n];
		uint32_t ranges[cfmap_n];
		for (size_t k = 0; k < cfmap_n; k++) {
			owners[k] = cfmap[k].owner;
			types[k] = cfmap[k].type;
			ranges[k] = cfmap[k].range;
		}
		int trc = transition_table_mark_entries_strict(owners, types, ranges, cfmap_n);
		if (trc != 0) {
			INFO("strict: failed to mark entries as strict\n");
			return PVAL_ECFG_MISMATCH;
		}
	}
	transition_table_pretty_print();

	return PVAL_OK;
}

/* Test 1: Non-strict check with matching CF in self and peer */
static void test_check_cf_compatibility_matching(void)
{
	printf("\n=== Test 1: check_cf_compatibility with matching CFs ===\n");
	
	struct parsed_payload self_cfg = {0};
	struct parsed_payload peer_cfg = {0};
	
	/* Setup self: one CF with owner=1, type=2, range=10, policy=5 */
	self_cfg.num_cfs = 1;
	self_cfg.cfs[0].owner_vm_index = 1;
	self_cfg.cfs[0].type = 2;
	self_cfg.cfs[0].range[0] = 10;
	self_cfg.cfs[0].range_len = 1;
	self_cfg.cfs[0].policy = 5;
	
	self_cfg.num_vms = 2;
	self_cfg.self_vm_index = 0;
	self_cfg.vms[0].hash = 0x1000;
	self_cfg.vms[1].hash = 0x2000;
	
	/* Setup peer: same CF */
	peer_cfg.num_cfs = 1;
	peer_cfg.cfs[0].owner_vm_index = 1;
	peer_cfg.cfs[0].type = 2;
	peer_cfg.cfs[0].range[0] = 10;
	peer_cfg.cfs[0].range_len = 1;
	peer_cfg.cfs[0].policy = 5;
	
	peer_cfg.num_vms = 2;
	peer_cfg.self_vm_index = 0;
	peer_cfg.vms[0].hash = 0x1000;
	peer_cfg.vms[1].hash = 0x3000;
	
	int rc = check_cf_compatibility_test(&self_cfg, &peer_cfg, 1);
	assert(rc == PVAL_OK);
	printf("PASS: Matching CFs accepted\n");
}

/* Test 2: Non-strict check with policy mismatch */
static void test_check_cf_compatibility_mismatch(void)
{
	printf("\n=== Test 2: check_cf_compatibility with mismatched policy ===\n");
	
	struct parsed_payload self_cfg = {0};
	struct parsed_payload peer_cfg = {0};
	
	/* Self CF: owner=1, type=2, range=10, policy=5 */
	self_cfg.num_cfs = 1;
	self_cfg.cfs[0].owner_vm_index = 1;
	self_cfg.cfs[0].type = 2;
	self_cfg.cfs[0].range[0] = 10;
	self_cfg.cfs[0].range_len = 1;
	self_cfg.cfs[0].policy = 5;
	
	self_cfg.num_vms = 2;
	self_cfg.self_vm_index = 0;
	self_cfg.vms[0].hash = 0x1000;
	
	/* Peer CF: same owner/type/range but policy=7 (mismatch!) */
	peer_cfg.num_cfs = 1;
	peer_cfg.cfs[0].owner_vm_index = 1;
	peer_cfg.cfs[0].type = 2;
	peer_cfg.cfs[0].range[0] = 10;
	peer_cfg.cfs[0].range_len = 1;
	peer_cfg.cfs[0].policy = 7;  /* Different policy */
	
	peer_cfg.num_vms = 1;
	peer_cfg.self_vm_index = 0;
	
	int rc = check_cf_compatibility_test(&self_cfg, &peer_cfg, 1);
	assert(rc == PVAL_ECFG_MISMATCH);
	printf("PASS: Policy mismatch detected\n");
}

/* Test 3: Strict check with matching CFs */
static void test_check_cf_compatibility_strict_matching(void)
{
	printf("\n=== Test 3: check_cf_compatibility_strict with matching CFs ===\n");
	
	struct parsed_payload self_cfg = {0};
	struct parsed_payload peer_cfg = {0};
	
	/* Self CF */
	self_cfg.num_cfs = 1;
	self_cfg.cfs[0].owner_vm_index = 1;
	self_cfg.cfs[0].type = 2;
	self_cfg.cfs[0].range[0] = 10;
	self_cfg.cfs[0].range_len = 1;
	self_cfg.cfs[0].policy = 5;
	
	self_cfg.num_vms = 2;
	self_cfg.self_vm_index = 0;
	self_cfg.vms[0].hash = 0x1000;
	self_cfg.vms[1].hash = 0x2000;
	
	/* Peer CF (matching) */
	peer_cfg.num_cfs = 1;
	peer_cfg.cfs[0].owner_vm_index = 1;
	peer_cfg.cfs[0].type = 2;
	peer_cfg.cfs[0].range[0] = 10;
	peer_cfg.cfs[0].range_len = 1;
	peer_cfg.cfs[0].policy = 5;
	
	peer_cfg.num_vms = 1;
	peer_cfg.self_vm_index = 0;
	
	int rc = check_cf_compatibility_strict_test(&self_cfg, &peer_cfg, 1);
	assert(rc == PVAL_OK);
	printf("PASS: Strict matching CFs accepted\n");
}

/* Test 4: Strict check with mismatch */
static void test_check_cf_compatibility_strict_mismatch(void)
{
	printf("\n=== Test 4: check_cf_compatibility_strict with mismatched policy ===\n");
	
	struct parsed_payload self_cfg = {0};
	struct parsed_payload peer_cfg = {0};
	
	self_cfg.num_cfs = 1;
	self_cfg.cfs[0].owner_vm_index = 1;
	self_cfg.cfs[0].type = 2;
	self_cfg.cfs[0].range[0] = 10;
	self_cfg.cfs[0].range_len = 1;
	self_cfg.cfs[0].policy = 5;
	
	self_cfg.num_vms = 2;
	self_cfg.self_vm_index = 0;
	
	peer_cfg.num_cfs = 1;
	peer_cfg.cfs[0].owner_vm_index = 1;
	peer_cfg.cfs[0].type = 2;
	peer_cfg.cfs[0].range[0] = 10;
	peer_cfg.cfs[0].range_len = 1;
	peer_cfg.cfs[0].policy = 99;  /* Mismatch */
	
	peer_cfg.num_vms = 1;
	peer_cfg.self_vm_index = 0;
	
	int rc = check_cf_compatibility_strict_test(&self_cfg, &peer_cfg, 1);
	assert(rc == PVAL_ECFG_MISMATCH);
	printf("PASS: Strict policy mismatch detected\n");
}

int main(void)
{
	printf("Running check_cf_compatibility tests...\n");
	
	test_check_cf_compatibility_matching();
	test_check_cf_compatibility_mismatch();
	test_check_cf_compatibility_strict_matching();
	test_check_cf_compatibility_strict_mismatch();
	
	printf("\n=== All tests passed! ===\n");
	return 0;
}
