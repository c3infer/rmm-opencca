#ifndef TRANSITION_TABLE_H
#define TRANSITION_TABLE_H

#include <spinlock.h>
#include <debug.h>
#include <policy_parser.h>

/* Capacity mirrors the cfmap sizing used in the validator */
#define TRANSITION_TABLE_CAPACITY ((PARSER_MAX_MAPS + 1) * PARSER_MAX_CFS * PARSER_MAX_CF_RANGE)
#define TRANSITION_TABLE_PEERS_PER_ENTRY PARSER_MAX_VMS

typedef spinlock_t transition_table_lock_t;
extern transition_table_lock_t transitiontablelock;
void init_transition_table_lock_init(void);

typedef struct {
    uint16_t owner;
    uint16_t type;
    uint32_t range;
    uint16_t policy;
    bool strict;
    /* Peer hashes from the payload that validated this entry (if strict) */
    uint32_t peer_hashes[TRANSITION_TABLE_PEERS_PER_ENTRY];
    uint16_t peer_count;  /* number of peers in peer_hashes */
} transition_entry_t;

typedef struct {
    unsigned int count;
    transition_entry_t entries[TRANSITION_TABLE_CAPACITY];
} transition_table_t;

extern transition_table_t transitiontable;

/* Add a unique tuple; if exists, OR the strict flag and verify policy matches.
 * peer_hashes: array of peer VM hashes (from parsed_payload vms).
 * peer_count: length of peer_hashes (0 if self-only).
 * Returns 0 on success, -1 on overflow, -2 on policy mismatch, -3 on peer conflict.
 */
int transition_table_add(uint16_t owner, uint16_t type, uint32_t range, uint16_t policy, bool strict, 
                         const uint32_t *peer_hashes, uint16_t peer_count);

/* Mark all table entries that match the given (owner, type, range) list as strict.
 * Called after strict validation succeeds to lock in the validated tuples.
 * Returns 0 on success, -1 if a tuple from the list is not found in the table.
 */
int transition_table_mark_entries_strict(const uint16_t *owners,
                                        const uint16_t *types,
                                        const uint32_t *ranges,
                                        size_t n_tuples);

/* Check if all non-strict entries in the table match the given CF list.
 * Used in strict mode: ensures no pre-existing (non-strict) table entries
 * conflict with the current validation.
 * Returns 0 if OK, -1 if a conflict is found.
 */
int transition_table_strict_check_no_conflicts(const uint16_t *owners,
                                              const uint16_t *types,
                                              const uint32_t *ranges,
                                              size_t n_tuples);

/* Check if the table has any strict entries.
 * Returns 1 if strict entries exist, 0 otherwise.
 */
int transition_table_has_strict_entries(void);

/* Check if a specific CF tuple exists in the table.
 * Returns 1 if found, 0 if not found.
 */
int transition_table_entry_exists(uint16_t owner, uint16_t type, uint32_t range);

/* Lookup policy for a specific CF tuple.
 * Returns 1 if found (*out_policy filled), 0 if not found, -1 on bad args.
 */
int transition_table_get_policy(uint16_t owner, uint16_t type, uint32_t range,
                                uint16_t *out_policy);

void transition_table_pretty_print(void);

#endif
