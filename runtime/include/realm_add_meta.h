#ifndef REALM_ADD_META_H
#define REALM_ADD_META_H

#include <spinlock.h>
#include <debug.h>
#include <measurement.h>
#include <string.h>
#include <stdio.h>
#include <policy_parser.h>
#include <stdbool.h>

typedef spinlock_t ram_lock_t;
extern ram_lock_t ramlock;
void init_ram_lock_init(void);

typedef struct {
    bool has_hash;                          /* hash may be populated later */
    unsigned long hash;
    unsigned char rim[MAX_MEASUREMENT_SIZE];
    unsigned long rd_addr;
    unsigned long pd_addr;
} type_rim_t;

typedef struct {
    unsigned int count;
    type_rim_t e[PARSER_MAX_VMS];
} ram_t;

extern ram_t ram;

/*
 * Phase 1: add rim + rd_addr + pd_addr (hash not yet known).
 * Uniqueness: rd_addr unique; pd_addr unique; rim unique (avoid ambiguity).
 * Returns 1 on success, 0 on failure.
 */
int ram_add_entry_rim(const unsigned char rim[MAX_MEASUREMENT_SIZE],
                      unsigned long rd_addr,
                      unsigned long pd_addr);

/*
 * Phase 2: add hash later, keyed by pd_addr.
 * Uniqueness: hash must be unique across all entries that already have a hash.
 * Also rejects if pd_addr not found or target already has hash.
 * Returns 1 on success, 0 on failure.
 */
int ram_add_hash_for_pd(unsigned long hash, unsigned long pd_addr);

/*
 * Lookups copy the found entry into *out (if out != NULL).
 * Return 1 if found, 0 if not found (or bad args).
 *
 * If not found and out != NULL, *out is zeroed.
 */
int ram_get_entry_from_hash(unsigned long hash, type_rim_t *out);
int ram_get_entry_from_rim(const unsigned char rim[MAX_MEASUREMENT_SIZE], type_rim_t *out);
int ram_get_entry_from_rd(unsigned long rd_addr, type_rim_t *out);
int ram_get_entry_from_pd(unsigned long pd_addr, type_rim_t *out);
int ram_remove_entry_from_rd(unsigned long rd_addr);
int ram_remove_entry_from_pd(unsigned long pd_addr);
unsigned int ram_scrub_stale_entries(void);

void ram_pretty_print(void);

#endif
