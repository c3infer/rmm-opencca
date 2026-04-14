#ifndef POLICY_PARSER_TEST_H
#define POLICY_PARSER_TEST_H

#include <stdint.h>
#include <stdbool.h>

#define PARSER_MAX_MAPS 4
#define PARSER_MAX_CFS 8
#define PARSER_MAX_CF_RANGE 4
#define PARSER_MAX_VMS 8
#define PARSER_MAX_MEMS 4

/* Minimal types used by policy_validator.c for unit testing */
#define VM_IDX_ANY 0xFFFF

typedef struct {
	unsigned long rd_addr;
	unsigned long pd_addr;
} type_rim_t;

#define GRANULE_SHIFT 12
#define SGT_MAX_ENTRIES 1024


/* parsed structures (minimal subset) */
struct parsed_mapping {
	uint16_t vm_index;
	uint64_t gpa;
	uint16_t prot;
	int32_t any_count;
	int peer_map_status;
};

struct parsed_mem {
	char name[4];
	uint16_t type;
	uint16_t status;
	uint64_t size;
	uint16_t num_mappings;
	struct parsed_mapping mappings[PARSER_MAX_MAPS];
};

struct parsed_cf {
	uint16_t owner_vm_index;
	uint16_t type;
	uint16_t policy;
	uint32_t range[PARSER_MAX_CF_RANGE];
	size_t range_len;
};

struct parsed_vm {
	uint32_t hash;
	uint8_t is_gateway;
	uint8_t strict;
	char name[4];
};

struct parsed_payload {
	uint16_t num_mems;
	uint16_t num_vms;
	uint16_t num_cfs;
	uint16_t self_vm_index;
	struct parsed_mem mems[PARSER_MAX_MEMS];
	struct parsed_vm vms[PARSER_MAX_VMS];
	struct parsed_cf cfs[PARSER_MAX_CFS];
};

/* constants */
#define MEM_PROTECTED 1
#define MEM_STATUS_VALIDATED 2

#define MAP_STATUS_NONE 0
#define MAP_STATUS_ACTIVE 1

/* PVAL codes */
#define PVAL_OK 0
#define PVAL_EARGS -10
#define PVAL_ENOMEM_NOTFOUND -11
#define PVAL_ECFG_MISMATCH -12
#define PVAL_EWRITEBACK -13
#define PVAL_ESGT -14
#define PVAL_ESGT_COVERAGE -15
#define PVAL_ESGT_CONFLICT -16
#define PVAL_ESGT_RD_ILLEGAL -17

#endif
