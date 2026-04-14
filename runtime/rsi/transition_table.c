#include <transition_table.h>

transition_table_lock_t transitiontablelock;
transition_table_t transitiontable = {.count = 0};

static inline void transition_table_lock_init(transition_table_lock_t *l) {
    l->val = 0U;
}

static inline void transition_table_lock(transition_table_lock_t *l) {
    spinlock_acquire(l);
}

static inline void transition_table_unlock(transition_table_lock_t *l) {
    spinlock_release(l);
}

void init_transition_table_lock_init(void) {
    transition_table_lock_init(&transitiontablelock);
}

int transition_table_add(uint16_t owner, uint16_t type, uint32_t range, uint16_t policy, bool strict, 
                         const uint32_t *peer_hashes, uint16_t peer_count) {
    int ret = 0;

    if (peer_count > TRANSITION_TABLE_PEERS_PER_ENTRY)
        peer_count = TRANSITION_TABLE_PEERS_PER_ENTRY;

    transition_table_lock(&transitiontablelock);

    /* check if present */
    for (unsigned int i = 0; i < transitiontable.count; i++) {
        transition_entry_t *e = &transitiontable.entries[i];
        if (e->owner == owner && e->type == type && e->range == range) {
            /* policy mismatch is an error */
            if (e->policy != policy) {
                ret = -2;
                goto out;
            }
            /* If the entry already exists with the same policy, treat this as
             * a repeated/duplicate add (no-op). Do not reject non-strict adds
             * here — conflicts are only signaled on policy mismatch or when
             * strict peer sets differ for strict additions.
             */
            /* If trying to add strict: check peer compatibility */
            if (strict && e->peer_count > 0 && peer_count > 0) {
                /* Strict entries must have matching peer sets */
                if (e->peer_count != peer_count) {
                    ret = -3;
                    goto out;
                }
                for (uint16_t i = 0; i < peer_count; i++) {
                    bool found = false;
                    for (uint16_t j = 0; j < e->peer_count; j++) {
                        if (e->peer_hashes[j] == peer_hashes[i]) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        ret = -3;
                        goto out;
                    }
                }
            }
            /* OR the strict flag */
            e->strict = e->strict || strict;
            /* Update peer list if new entry has peers and existing doesn't */
            if (peer_count > 0 && e->peer_count == 0) {
                e->peer_count = peer_count;
                for (uint16_t i = 0; i < peer_count; i++) {
                    e->peer_hashes[i] = peer_hashes[i];
                }
            }
            goto out;
        }
    }

    if (transitiontable.count >= TRANSITION_TABLE_CAPACITY) {
        ret = -1;
        goto out;
    }

    transition_entry_t *ne = &transitiontable.entries[transitiontable.count++];
    ne->owner = owner;
    ne->type = type;
    ne->range = range;
    ne->policy = policy;
    ne->strict = strict;
    ne->peer_count = peer_count;
    for (uint16_t i = 0; i < peer_count; i++) {
        ne->peer_hashes[i] = peer_hashes[i];
    }

out:
    transition_table_unlock(&transitiontablelock);
    return ret;
}

void transition_table_pretty_print(void) {
    transition_table_lock(&transitiontablelock);

    INFO("Transition table: %u entr%s\n", transitiontable.count, transitiontable.count == 1 ? "y" : "ies");
    for (unsigned int i = 0; i < transitiontable.count; i++) {
        transition_entry_t *e = &transitiontable.entries[i];
        INFO("TT[%u]: owner=%u type=%u range=%u policy=%u strict=%u peers=%u",
             i, (unsigned)e->owner, (unsigned)e->type, (unsigned)e->range, (unsigned)e->policy, (unsigned)e->strict, (unsigned)e->peer_count);
        for (uint16_t j = 0; j < e->peer_count; j++) {
            INFO(" 0x%x", (unsigned)e->peer_hashes[j]);
        }
        INFO("\n");
    }

    transition_table_unlock(&transitiontablelock);
}

/* Mark all table entries matching (owner, type, range) list as strict.
 * Returns 0 if all found and marked, -1 if any tuple not found.
 */
int transition_table_mark_entries_strict(const uint16_t *owners,
                                        const uint16_t *types,
                                        const uint32_t *ranges,
                                        size_t n_tuples)
{
    if (!owners || !types || !ranges || n_tuples == 0)
        return 0;

    int ret = 0;
    transition_table_lock(&transitiontablelock);

    for (size_t i = 0; i < n_tuples; i++) {
        uint16_t o = owners[i];
        uint16_t t = types[i];
        uint32_t r = ranges[i];
        bool found = false;

        for (unsigned int j = 0; j < transitiontable.count; j++) {
            transition_entry_t *e = &transitiontable.entries[j];
            if (e->owner == o && e->type == t && e->range == r) {
                e->strict = true;
                found = true;
                INFO("transition_table: marked entry strict owner=%u type=%u range=%u\n",
                     (unsigned)o, (unsigned)t, (unsigned)r);
                break;
            }
        }

        if (!found) {
            INFO("transition_table: entry not found to mark strict owner=%u type=%u range=%u\n",
                 (unsigned)o, (unsigned)t, (unsigned)r);
            ret = -1;
            goto out;
        }
    }

out:
    transition_table_unlock(&transitiontablelock);
    return ret;
}

/* Check if all non-strict table entries are covered by the CF validation list.
 * Returns 0 if no conflicts, -1 if a non-strict table entry is not in the CF list.
 */
int transition_table_strict_check_no_conflicts(const uint16_t *owners,
                                              const uint16_t *types,
                                              const uint32_t *ranges,
                                              size_t n_tuples)
{
    if (!owners || !types || !ranges || n_tuples == 0)
        return 0; /* No CFs to validate = nothing to conflict */

    int ret = 0;
    transition_table_lock(&transitiontablelock);

    /* For each non-strict entry in the table, check if it's in the CF list */
    for (unsigned int i = 0; i < transitiontable.count; i++) {
        transition_entry_t *e = &transitiontable.entries[i];

        if (e->strict)
            continue; /* Skip already-strict entries */

        /* Search for this entry in the CF validation list */
        bool found = false;
        for (size_t j = 0; j < n_tuples; j++) {
            if (e->owner == owners[j] && e->type == types[j] && e->range == ranges[j]) {
                found = true;
                break;
            }
        }

        if (!found) {
            INFO("transition_table: strict conflict: non-strict entry owner=%u type=%u range=%u not in CF validation list\n",
                 (unsigned)e->owner, (unsigned)e->type, (unsigned)e->range);
            ret = -1;
            goto out;
        }
    }

out:
    transition_table_unlock(&transitiontablelock);
    return ret;
}

/* Check if the table has any strict entries.
 * Returns 1 if strict entries exist, 0 otherwise.
 */
int transition_table_has_strict_entries(void)
{
    transition_table_lock(&transitiontablelock);

    for (unsigned int i = 0; i < transitiontable.count; i++) {
        if (transitiontable.entries[i].strict) {
            transition_table_unlock(&transitiontablelock);
            return 1;
        }
    }

    transition_table_unlock(&transitiontablelock);
    return 0;
}

/* Check if a specific CF tuple exists in the table.
 * Returns 1 if found, 0 if not found.
 */
int transition_table_entry_exists(uint16_t owner, uint16_t type, uint32_t range)
{
    transition_table_lock(&transitiontablelock);

    for (unsigned int i = 0; i < transitiontable.count; i++) {
        transition_entry_t *e = &transitiontable.entries[i];
        if (e->owner == owner && e->type == type && e->range == range) {
            transition_table_unlock(&transitiontablelock);
            return 1;
        }
    }

    transition_table_unlock(&transitiontablelock);
    return 0;
}

int transition_table_get_policy(uint16_t owner, uint16_t type, uint32_t range,
                                uint16_t *out_policy)
{
    if (out_policy == NULL) {
        return -1;
    }

    transition_table_lock(&transitiontablelock);

    for (unsigned int i = 0; i < transitiontable.count; i++) {
        transition_entry_t *e = &transitiontable.entries[i];
        if (e->owner == owner && e->type == type && e->range == range) {
            *out_policy = e->policy;
            transition_table_unlock(&transitiontablelock);
            return 1;
        }
    }

    transition_table_unlock(&transitiontablelock);
    return 0;
}
