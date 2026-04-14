#ifndef POLICY_PARSER_H
#define POLICY_PARSER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

/* Optional: for INFO/WARN like TF-RMM */
#include <debug.h>
#include <granule.h>
#include <debug.h>
#include <buffer.h>

#ifndef PARSER_MAX_VMS
#define PARSER_MAX_VMS  8
#endif

#ifndef PARSER_MAX_MEMS
#define PARSER_MAX_MEMS 8
#endif

#ifndef PARSER_MAX_MAPS
#define PARSER_MAX_MAPS 8
#endif

#ifndef PARSER_MAX_CFS
#define PARSER_MAX_CFS  8
#endif

#ifndef PARSER_MAX_CF_RANGE
#define PARSER_MAX_CF_RANGE 8
#endif

#define VM_IDX_ANY 0xFFFFu

#define PAYLOAD_MAGIC 0x504f4c59u /* 'POLY' (choose any stable magic) */

/* prot is stored, but validation against SGT can ignore it if desired */
enum {
	PROT_R  = 1,
	PROT_W  = 2,
	PROT_RW = 3,
};

enum {
	MEM_PROTECTED   = 1,
	MEM_UNPROTECTED = 2,
	MEM_OTHER = 3,
};

enum {
	CF_TYPE_CALL  = 1,
	CF_TYPE_EXCEPTION = 2,
	CF_TYPE_OTHER = 3,
};

enum {
	CF_POLICY_BLOCK = 1,
	CF_POLICY_ALLOW = 2,
	CF_POLICY_OTHER = 3,
};

struct parsed_vm {
	char     name[4];      /* "VM1" */
	uint32_t hash;
	uint8_t  is_gateway;
	uint8_t  strict;
	uint16_t reserved;
};

struct parsed_mapping {
	uint16_t vm_index;     /* VM index or VM_IDX_ANY */
	uint16_t prot;         /* PROT_* */
	uint64_t gpa;          /* base GPA */
	int32_t  any_count;    /* REQUIRED for ANY; ignored otherwise */
};

struct parsed_mem {
	char     name[4];      /* "Mem1" */
	uint64_t size;
	uint16_t type;         /* MEM_PROTECTED / MEM_UNPROTECTED */
	uint16_t num_mappings;

	struct parsed_mapping mappings[PARSER_MAX_MAPS];
};

struct parsed_cf {
	char     name[4];      /* "CF1" */
	uint16_t owner_vm_index;
	uint16_t type;         /* CF_TYPE_* */
	uint16_t policy;       /* CF_POLICY_* */
	uint16_t range_len;
	uint32_t range[PARSER_MAX_CF_RANGE];
};

struct parsed_payload {
	uint16_t self_vm_index;
	uint16_t num_vms;
	uint16_t num_mems;
	uint16_t num_cfs;

	struct parsed_vm  vms[PARSER_MAX_VMS];
	struct parsed_mem mems[PARSER_MAX_MEMS];
	struct parsed_cf  cfs[PARSER_MAX_CFS];
};

/*
 * Binary format v1 (little-endian), layout:
 *
 * Header (16 bytes):
 *   u32 magic
 *   u16 version (=1)
 *   u16 self_vm_index
 *   u16 num_vms
 *   u16 num_mems
 *   u16 num_cfs
 *   u16 reserved
 *
 * VM section: num_vms * VM_REC_SIZE
 *   VM_REC (12 bytes):
 *     char name[4]
 *     u32  hash
 *     u8   is_gateway
 *     u8   strict
 *     u16  reserved
 *
 * MEM section: num_mems blocks, each:
 *   MEM_HDR (16 bytes):
 *     char name[4]
 *     u64  size
 *     u16  type
 *     u16  num_maps
 *
 *   MAP section: num_maps * MAP_REC_SIZE
 *     MAP_REC (20 bytes):
 *       u16  vm_index    (VM_IDX_ANY allowed)
 *       u16  prot        (PROT_*)
 *       u64  gpa_base
 *       i32  any_count   (REQUIRED if vm_index==VM_IDX_ANY; else 0)
 *       u32  reserved
 *
 * CF section: num_cfs blocks, each:
 *   CF_HDR (12 bytes):
 *     char name[4]
 *     u16  owner_vm_index (0xFFFF allowed)
 *     u16  type
 *     u16  policy
 *     u16  range_len
 *
 *   CF_RANGE: range_len * u32
 *
 * The parser stores up to PARSER_MAX_* and skips the rest with WARN().
 */
int parse_payload(const uint8_t *buf, size_t len, struct parsed_payload *out);

bool load_cfg(unsigned long pd_addr, struct parsed_payload *cfg0, char expected_state, enum buffer_slot slot);
bool upload_cfg(unsigned long pd_addr, const struct parsed_payload *cfg0, char expected_state, enum buffer_slot slot);

void dump_parsed_payload(const struct parsed_payload *cfg);

#endif /* POLICY_PARSER_H */
