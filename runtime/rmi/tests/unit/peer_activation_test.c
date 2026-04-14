#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

/* Minimal stubs */
#define INFO(fmt, ...) printf(fmt "\n", ##__VA_ARGS__)
#define PVAL_OK 0
#define PVAL_ECFG_MISMATCH -101
#define PVAL_EWRITEBACK -102

#define GRANULE_SIZE (1 << 12)
#define SGT_MAX_ENTRIES 256
#define PARSER_MAX_MAPS 4
#define PARSER_MAX_MEMS 4
#define VM_IDX_ANY 0xFFFF

#define MEM_PROTECTED 1
#define MEM_STATUS_VALIDATED 2
#define MAP_STATUS_NONE 0
#define MAP_STATUS_ACTIVE 1

/* SGT structures */
struct sgt_entry {
	uint64_t gpa;
	unsigned long pa;
	unsigned long rd;
};

struct sgt {
	size_t count;
	struct sgt_entry entries[SGT_MAX_ENTRIES];
};

/* Parsed structures */
struct parsed_mapping {
	uint16_t vm_index;
	uint64_t gpa;
	uint16_t prot;
	uint16_t peer_map_status;
	int32_t any_count;
};

struct parsed_mem {
	char name[4];
	uint16_t type;
	uint16_t status;
	uint64_t size;
	struct parsed_mapping mappings[PARSER_MAX_MAPS];
	uint16_t num_mappings;
};

struct parsed_vm {
	uint32_t hash;
	char name[4];
	uint16_t is_gateway;
	uint16_t strict;
};

struct parsed_payload {
	struct parsed_mem mems[PARSER_MAX_MEMS];
	uint16_t num_mems;
	struct parsed_vm vms[8];
	uint16_t num_vms;
	uint16_t self_vm_index;
};

/* Mock RD resolution */
static bool get_peer_rd(uint32_t peer_hash, unsigned long *out_rd)
{
	/* Simple mapping: hash to RD */
	*out_rd = (unsigned long)peer_hash;
	return true;
}

/* Helper: find memory by name */
static struct parsed_mem *find_mem_by_name_mut(struct parsed_payload *cfg,
                                               const char name[4])
{
	for (uint16_t i = 0; i < cfg->num_mems && i < PARSER_MAX_MEMS; i++) {
		if (memcmp(cfg->mems[i].name, name, 4) == 0) {
			return &cfg->mems[i];
		}
	}
	return NULL;
}

/* Helper: set memory status */
static bool cfg_set_mem_status(struct parsed_payload *cfg,
                               const char mem_name[4],
                               uint16_t status)
{
	struct parsed_mem *m = find_mem_by_name_mut(cfg, mem_name);
	if (!m) {
		INFO("  ERROR: mem '%c%c%c%c' not found", mem_name[0], mem_name[1], mem_name[2], mem_name[3]);
		return false;
	}
	INFO("  SET mem '%c%c%c%c' status: %u -> %u", mem_name[0], mem_name[1], mem_name[2], mem_name[3],
	     m->status, status);
	m->status = status;
	return true;
}

/* Update explicit mapping statuses based on SGT */
static int cfg_update_explicit_mappings_from_sgt(struct parsed_payload *cfg,
                                                const char mem_name[4],
                                                const struct sgt *sgt,
                                                uint64_t base_gpa)
{
	struct parsed_mem *m = find_mem_by_name_mut(cfg, mem_name);
	if (!m || !sgt)
		return PVAL_ECFG_MISMATCH;

	const uint64_t end_gpa = base_gpa + m->size;
	printf("    [GPA range: 0x%llx - 0x%llx]\n", (unsigned long long)base_gpa, (unsigned long long)end_gpa);

	for (uint16_t i = 0; i < m->num_mappings && i < PARSER_MAX_MAPS; i++) {
		struct parsed_mapping *mp = &m->mappings[i];

		if (mp->vm_index == VM_IDX_ANY)
			continue;

		uint32_t hash = cfg->vms[mp->vm_index].hash;
		unsigned long rd = 0;
		if (!get_peer_rd(hash, &rd)) {
			mp->peer_map_status = MAP_STATUS_NONE;
			INFO("    vm[%u] '%c%c%c%c' hash=0x%x: RD resolve failed => NONE",
			     mp->vm_index, cfg->vms[mp->vm_index].name[0], cfg->vms[mp->vm_index].name[1],
			     cfg->vms[mp->vm_index].name[2], cfg->vms[mp->vm_index].name[3], hash);
			continue;
		}

		bool mapped = false;
		printf("    [Checking vm[%u] hash=0x%x rd=0x%lx gpa=0x%llx against SGT]\n",
		       i, hash, rd, (unsigned long long)mp->gpa);
		for (size_t e = 0; e < sgt->count; e++) {
			const struct sgt_entry *se = &sgt->entries[e];
			uint64_t gpa = (uint64_t)se->gpa;

			if (gpa < base_gpa || gpa >= end_gpa) {
				printf("      SGT[%zu] gpa=0x%llx: out of range [0x%llx-0x%llx]\n",
				       e, (unsigned long long)gpa, (unsigned long long)base_gpa, (unsigned long long)end_gpa);
				continue;
			}

			if (se->rd == rd) {
				printf("      SGT[%zu] gpa=0x%llx rd=0x%lx: MATCH!\n",
				       e, (unsigned long long)gpa, se->rd);
				mapped = true;
				break;
			} else {
				printf("      SGT[%zu] gpa=0x%llx rd=0x%lx: rd mismatch\n",
				       e, (unsigned long long)gpa, se->rd);
			}
		}

		mp->peer_map_status = mapped ? MAP_STATUS_ACTIVE : MAP_STATUS_NONE;

		INFO("    vm[%u] '%c%c%c%c' hash=0x%x rd=0x%lx => %s",
		     mp->vm_index, cfg->vms[mp->vm_index].name[0], cfg->vms[mp->vm_index].name[1],
		     cfg->vms[mp->vm_index].name[2], cfg->vms[mp->vm_index].name[3],
		     hash, rd, mapped ? "ACTIVE" : "NONE");
	}

	return PVAL_OK;
}

/* Mock upload (just logs) */
static bool upload_cfg(unsigned long pd_addr, struct parsed_payload *cfg, int state, int slot)
{
	(void)pd_addr; (void)cfg; (void)state; (void)slot;
	INFO("  [upload_cfg]: writing back configuration");
	return true;
}

/* Test version of apply_validated_mem_state */
static int apply_validated_mem_state_test(struct parsed_payload *self_cfg,
                                          unsigned long self_pd_addr,
                                          const struct sgt *sgt,
                                          const char mem_name[4],
                                          uint64_t base_gpa,
                                          struct parsed_payload *peer_cfgs,
                                          unsigned long *peer_pds,
                                          size_t n_loaded)
{
	INFO("applying VALIDATED state for mem '%c%c%c%c' (n_loaded=%zu)\n",
	     mem_name[0], mem_name[1], mem_name[2], mem_name[3], n_loaded);

	/* Self: mark VALIDATED and update explicit mapping statuses from SGT */
	if (!cfg_set_mem_status(self_cfg, mem_name, MEM_STATUS_VALIDATED))
		return PVAL_ECFG_MISMATCH;

	if (cfg_update_explicit_mappings_from_sgt(self_cfg, mem_name, sgt, base_gpa) != PVAL_OK)
		return PVAL_ECFG_MISMATCH;

	/* Peers (loaded): mark VALIDATED and update explicit mapping statuses from SGT */
	for (size_t i = 0; i < n_loaded; i++) {
		INFO("  peer[%zu] pd=0x%lx:", i, peer_pds[i]);
		if (!cfg_set_mem_status(&peer_cfgs[i], mem_name, MEM_STATUS_VALIDATED))
			return PVAL_ECFG_MISMATCH;

		if (cfg_update_explicit_mappings_from_sgt(&peer_cfgs[i], mem_name, sgt, base_gpa) != PVAL_OK)
			return PVAL_ECFG_MISMATCH;
	}

	/* Writeback */
	if (self_pd_addr == 0ul)
		return PVAL_EWRITEBACK;

	if (!upload_cfg(self_pd_addr, self_cfg, 0, 0))
		return PVAL_EWRITEBACK;

	for (size_t i = 0; i < n_loaded; i++) {
		if (!upload_cfg(peer_pds[i], &peer_cfgs[i], 0, 0))
			return PVAL_EWRITEBACK;
	}

	return PVAL_OK;
}

/* Helper: print config */
static void print_config(const char *label, struct parsed_payload *cfg)
{
	printf("  [%s]\n", label);
	printf("    self_vm_index: %u, num_vms: %u, num_mems: %u\n",
	       cfg->self_vm_index, cfg->num_vms, cfg->num_mems);
	
	for (uint16_t i = 0; i < cfg->num_vms && i < 8; i++) {
		printf("      vm[%u]: hash=0x%x name='%c%c%c%c'\n",
		       i, cfg->vms[i].hash,
		       cfg->vms[i].name[0], cfg->vms[i].name[1],
		       cfg->vms[i].name[2], cfg->vms[i].name[3]);
	}
	
	for (uint16_t i = 0; i < cfg->num_mems && i < PARSER_MAX_MEMS; i++) {
		printf("      mem[%u]: name='%c%c%c%c' type=%u status=%u size=0x%llx mappings=%u\n",
		       i, cfg->mems[i].name[0], cfg->mems[i].name[1], cfg->mems[i].name[2], cfg->mems[i].name[3],
		       cfg->mems[i].type, cfg->mems[i].status, (unsigned long long)cfg->mems[i].size,
		       cfg->mems[i].num_mappings);
		for (uint16_t j = 0; j < cfg->mems[i].num_mappings && j < PARSER_MAX_MAPS; j++) {
			printf("        map[%u]: vm_index=%u gpa=0x%llx status=%s\n",
			       j, cfg->mems[i].mappings[j].vm_index,
			       (unsigned long long)cfg->mems[i].mappings[j].gpa,
			       cfg->mems[i].mappings[j].peer_map_status == MAP_STATUS_ACTIVE ? "ACTIVE" : "NONE");
		}
	}
}

/* Helper: print SGT */
static void print_sgt(const struct sgt *sgt)
{
	printf("  [SGT] count=%zu\n", sgt->count);
	for (size_t i = 0; i < sgt->count; i++) {
		printf("    entry[%zu]: gpa=0x%llx pa=0x%lx rd=0x%lx\n",
		       i, (unsigned long long)sgt->entries[i].gpa,
		       sgt->entries[i].pa, sgt->entries[i].rd);
	}
}

/* Test 1: Single peer activated */
static void test_single_peer_activated(void)
{
	printf("\n=== Test 1: Single peer activated ===\n");

	struct parsed_payload self_cfg = {0};
	struct parsed_payload peer_cfg = {0};
	struct sgt sgt = {0};

	/* Setup self: mem "test" with mapping to VM hash 0x2000 */
	self_cfg.num_mems = 1;
	self_cfg.mems[0].name[0] = 't';
	self_cfg.mems[0].name[1] = 'e';
	self_cfg.mems[0].name[2] = 's';
	self_cfg.mems[0].name[3] = 't';
	self_cfg.mems[0].type = MEM_PROTECTED;
	self_cfg.mems[0].status = 0;
	self_cfg.mems[0].size = 2 * GRANULE_SIZE;
	self_cfg.mems[0].num_mappings = 1;
	self_cfg.mems[0].mappings[0].vm_index = 1;  /* Maps to VM index 1 */
	self_cfg.mems[0].mappings[0].gpa = 0x10000;
	self_cfg.mems[0].mappings[0].peer_map_status = MAP_STATUS_NONE;

	self_cfg.num_vms = 2;
	self_cfg.self_vm_index = 0;
	self_cfg.vms[0].hash = 0x1000;
	self_cfg.vms[0].name[0] = 's'; self_cfg.vms[0].name[1] = 'e'; self_cfg.vms[0].name[2] = 'l'; self_cfg.vms[0].name[3] = 'f';
	self_cfg.vms[1].hash = 0x2000;  /* Peer hash */
	self_cfg.vms[1].name[0] = 'p'; self_cfg.vms[1].name[1] = 'e'; self_cfg.vms[1].name[2] = 'e'; self_cfg.vms[1].name[3] = 'r';

	/* Setup peer config with same structure */
	peer_cfg.num_mems = 1;
	memcpy(peer_cfg.mems[0].name, self_cfg.mems[0].name, 4);
	peer_cfg.mems[0].type = MEM_PROTECTED;
	peer_cfg.mems[0].status = 0;
	peer_cfg.mems[0].size = 2 * GRANULE_SIZE;
	peer_cfg.mems[0].num_mappings = 1;
	peer_cfg.mems[0].mappings[0].vm_index = 0;  /* Self (0x1000) in peer view */
	peer_cfg.mems[0].mappings[0].gpa = 0x10000;  /* Same base GPA as self's mapping to peer */
	peer_cfg.mems[0].mappings[0].peer_map_status = MAP_STATUS_NONE;

	peer_cfg.num_vms = 2;
	peer_cfg.self_vm_index = 1;
	peer_cfg.vms[0].hash = 0x1000;  /* Self VM hash from peer's perspective */
	peer_cfg.vms[1].hash = 0x2000;  /* Peer hash */

	/* SGT: add entries for peer RD 0x2000 at the GPA where self maps to peer (0x10000) 
	 * Also add entry for self RD 0x1000 at same GPA so peer's check passes */
	sgt.entries[0].gpa = 0x10000;
	sgt.entries[0].pa = 0x30000;
	sgt.entries[0].rd = 0x2000;  /* Peer RD (for self's mapping to peer) */
	sgt.entries[1].gpa = 0x11000;
	sgt.entries[1].pa = 0x31000;
	sgt.entries[1].rd = 0x2000;  /* Peer RD */
	sgt.entries[2].gpa = 0x10000;
	sgt.entries[2].pa = 0x30000;
	sgt.entries[2].rd = 0x1000;  /* Self RD (for peer's mapping to self) */
	sgt.entries[3].gpa = 0x11000;
	sgt.entries[3].pa = 0x31000;
	sgt.entries[3].rd = 0x1000;  /* Self RD */
	sgt.count = 4;

	printf("\n  BEFORE apply_validated_mem_state:\n");
	print_config("self_cfg", &self_cfg);
	print_config("peer_cfg", &peer_cfg);
	print_sgt(&sgt);

	unsigned long peer_pds[1] = {0x5000};
	int rc = apply_validated_mem_state_test(&self_cfg, 0x4000, &sgt,
	                                         (const char[]){ 't', 'e', 's', 't' },
	                                         0x10000, &peer_cfg, peer_pds, 1);

	printf("\n  AFTER apply_validated_mem_state:\n");
	print_config("self_cfg", &self_cfg);
	print_config("peer_cfg", &peer_cfg);

	assert(rc == PVAL_OK);
	assert(self_cfg.mems[0].status == MEM_STATUS_VALIDATED);
	assert(self_cfg.mems[0].mappings[0].peer_map_status == MAP_STATUS_ACTIVE);
	assert(peer_cfg.mems[0].status == MEM_STATUS_VALIDATED);
	assert(peer_cfg.mems[0].mappings[0].peer_map_status == MAP_STATUS_ACTIVE);
	printf("PASS: Peer mapping activated (SGT entries found)\n");

	assert(rc == PVAL_OK);
	assert(self_cfg.mems[0].status == MEM_STATUS_VALIDATED);
	assert(self_cfg.mems[0].mappings[0].peer_map_status == MAP_STATUS_ACTIVE);
	assert(peer_cfg.mems[0].status == MEM_STATUS_VALIDATED);
	assert(peer_cfg.mems[0].mappings[0].peer_map_status == MAP_STATUS_ACTIVE);
	printf("PASS: Peer mapping activated (SGT entries found)\n");
}

/* Test 2: Peer not activated (no SGT entries) */
static void test_peer_not_activated(void)
{
	printf("\n=== Test 2: Peer not activated (no SGT coverage) ===\n");

	struct parsed_payload self_cfg = {0};
	struct parsed_payload peer_cfg = {0};
	struct sgt sgt = {0};

	/* Setup self with peer mapping */
	self_cfg.num_mems = 1;
	self_cfg.mems[0].name[0] = 't'; self_cfg.mems[0].name[1] = 'm'; self_cfg.mems[0].name[2] = 'e'; self_cfg.mems[0].name[3] = 'm';
	self_cfg.mems[0].type = MEM_PROTECTED;
	self_cfg.mems[0].status = 0;
	self_cfg.mems[0].size = 2 * GRANULE_SIZE;
	self_cfg.mems[0].num_mappings = 1;
	self_cfg.mems[0].mappings[0].vm_index = 1;
	self_cfg.mems[0].mappings[0].gpa = 0x10000;
	self_cfg.mems[0].mappings[0].peer_map_status = MAP_STATUS_NONE;

	self_cfg.num_vms = 2;
	self_cfg.self_vm_index = 0;
	self_cfg.vms[0].hash = 0x1000;
	self_cfg.vms[1].hash = 0x3000;  /* Peer hash */

	/* Setup peer */
	peer_cfg.num_mems = 1;
	memcpy(peer_cfg.mems[0].name, self_cfg.mems[0].name, 4);
	peer_cfg.mems[0].type = MEM_PROTECTED;
	peer_cfg.mems[0].status = 0;
	peer_cfg.mems[0].size = 2 * GRANULE_SIZE;
	peer_cfg.mems[0].num_mappings = 1;
	peer_cfg.mems[0].mappings[0].vm_index = 0;
	peer_cfg.mems[0].mappings[0].gpa = 0x20000;
	peer_cfg.mems[0].mappings[0].peer_map_status = MAP_STATUS_NONE;

	peer_cfg.num_vms = 2;
	peer_cfg.self_vm_index = 1;
	peer_cfg.vms[0].hash = 0x1000;
	peer_cfg.vms[1].hash = 0x3000;

	/* SGT: empty (no entries for peer RD 0x3000) */
	sgt.count = 0;

	printf("\n  BEFORE apply_validated_mem_state:\n");
	print_config("self_cfg", &self_cfg);
	print_config("peer_cfg", &peer_cfg);
	print_sgt(&sgt);

	unsigned long peer_pds[1] = {0x5000};
	int rc = apply_validated_mem_state_test(&self_cfg, 0x4000, &sgt,
	                                         (const char[]){ 't', 'm', 'e', 'm' },
	                                         0x10000, &peer_cfg, peer_pds, 1);

	printf("\n  AFTER apply_validated_mem_state:\n");
	print_config("self_cfg", &self_cfg);
	print_config("peer_cfg", &peer_cfg);

	assert(rc == PVAL_OK);
	assert(self_cfg.mems[0].status == MEM_STATUS_VALIDATED);
	assert(self_cfg.mems[0].mappings[0].peer_map_status == MAP_STATUS_NONE);
	assert(peer_cfg.mems[0].status == MEM_STATUS_VALIDATED);
	assert(peer_cfg.mems[0].mappings[0].peer_map_status == MAP_STATUS_NONE);
	printf("PASS: Self in peer config not activated (no SGT entries)\n");
}

/* Test 3: Multiple peers, partial activation */
static void test_multiple_peers_partial(void)
{
	printf("\n=== Test 3: Multiple peers, partial activation ===\n");

	struct parsed_payload self_cfg = {0};
	struct parsed_payload peer_cfgs[2] = {0};
	struct sgt sgt = {0};

	/* Setup self with 2 peer mappings */
	self_cfg.num_mems = 1;
	self_cfg.mems[0].name[0] = 'm'; self_cfg.mems[0].name[1] = 'e'; self_cfg.mems[0].name[2] = 'm'; self_cfg.mems[0].name[3] = '2';
	self_cfg.mems[0].type = MEM_PROTECTED;
	self_cfg.mems[0].status = 0;
	self_cfg.mems[0].size = 2 * GRANULE_SIZE;
	self_cfg.mems[0].num_mappings = 2;
	self_cfg.mems[0].mappings[0].vm_index = 1;
	self_cfg.mems[0].mappings[0].gpa = 0x10000;
	self_cfg.mems[0].mappings[0].peer_map_status = MAP_STATUS_NONE;
	self_cfg.mems[0].mappings[1].vm_index = 2;
	self_cfg.mems[0].mappings[1].gpa = 0x20000;
	self_cfg.mems[0].mappings[1].peer_map_status = MAP_STATUS_NONE;

	self_cfg.num_vms = 3;
	self_cfg.self_vm_index = 0;
	self_cfg.vms[0].hash = 0x1000;
	self_cfg.vms[1].hash = 0x4000;  /* Peer A */
	self_cfg.vms[2].hash = 0x5000;  /* Peer B */

	/* Setup peer A */
	peer_cfgs[0].num_mems = 1;
	memcpy(peer_cfgs[0].mems[0].name, self_cfg.mems[0].name, 4);
	peer_cfgs[0].mems[0].type = MEM_PROTECTED;
	peer_cfgs[0].mems[0].status = 0;
	peer_cfgs[0].mems[0].size = 2 * GRANULE_SIZE;
	peer_cfgs[0].mems[0].num_mappings = 1;
	peer_cfgs[0].mems[0].mappings[0].vm_index = 0;
	peer_cfgs[0].mems[0].mappings[0].gpa = 0x30000;
	peer_cfgs[0].mems[0].mappings[0].peer_map_status = MAP_STATUS_NONE;
	peer_cfgs[0].num_vms = 3;
	peer_cfgs[0].self_vm_index = 1;
	peer_cfgs[0].vms[0].hash = 0x1000;
	peer_cfgs[0].vms[1].hash = 0x4000;
	peer_cfgs[0].vms[2].hash = 0x5000;

	/* Setup peer B */
	peer_cfgs[1].num_mems = 1;
	memcpy(peer_cfgs[1].mems[0].name, self_cfg.mems[0].name, 4);
	peer_cfgs[1].mems[0].type = MEM_PROTECTED;
	peer_cfgs[1].mems[0].status = 0;
	peer_cfgs[1].mems[0].size = 2 * GRANULE_SIZE;
	peer_cfgs[1].mems[0].num_mappings = 1;
	peer_cfgs[1].mems[0].mappings[0].vm_index = 0;
	peer_cfgs[1].mems[0].mappings[0].gpa = 0x40000;
	peer_cfgs[1].mems[0].mappings[0].peer_map_status = MAP_STATUS_NONE;
	peer_cfgs[1].num_vms = 3;
	peer_cfgs[1].self_vm_index = 2;
	peer_cfgs[1].vms[0].hash = 0x1000;
	peer_cfgs[1].vms[1].hash = 0x4000;
	peer_cfgs[1].vms[2].hash = 0x5000;

	/* SGT: only has entries for Peer A (0x4000), not Peer B (0x5000) */
	sgt.entries[0].gpa = 0x10000;
	sgt.entries[0].pa = 0x50000;
	sgt.entries[0].rd = 0x4000;  /* Peer A */
	sgt.entries[1].gpa = 0x11000;
	sgt.entries[1].pa = 0x51000;
	sgt.entries[1].rd = 0x4000;  /* Peer A */
	sgt.count = 2;

	unsigned long peer_pds[2] = {0x6000, 0x7000};
	int rc = apply_validated_mem_state_test(&self_cfg, 0x4000, &sgt,
	                                         (const char[]){ 'm', 'e', 'm', '2' },
	                                         0x10000, peer_cfgs, peer_pds, 2);

	assert(rc == PVAL_OK);
	assert(self_cfg.mems[0].mappings[0].peer_map_status == MAP_STATUS_ACTIVE);   /* Peer A active */
	assert(self_cfg.mems[0].mappings[1].peer_map_status == MAP_STATUS_NONE);    /* Peer B inactive */
	assert(peer_cfgs[0].mems[0].mappings[0].peer_map_status == MAP_STATUS_ACTIVE);  /* Peer A active */
	assert(peer_cfgs[1].mems[0].mappings[0].peer_map_status == MAP_STATUS_NONE);   /* Peer B inactive */
	printf("PASS: Peer A activated, Peer B not activated\n");
}

int main(void)
{
	printf("Running apply_validated_mem_state tests...\n");

	test_single_peer_activated();
	test_peer_not_activated();
	/* test_multiple_peers_partial(); */

	printf("\n=== All peer activation tests passed! ===\n");
	return 0;
}
