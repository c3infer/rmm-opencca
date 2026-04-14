#include <realm_add_meta.h>
#include <granule.h>

ram_lock_t ramlock;
ram_t ram = { .count = 0 };

static inline void ram_lock_init(ram_lock_t *l)
{
    /* .bss will zero ramlock, but make init explicit for safety */
    l->val = 0U;
}

static inline void ram_lock(ram_lock_t *l)
{
    spinlock_acquire(l);
}

static inline void ram_unlock(ram_lock_t *l)
{
    spinlock_release(l);
}

void init_ram_lock_init(void)
{
    /* .bss will zero ramlock, but make init explicit for safety */
    ram_lock_init(&ramlock);
}

int ram_add_entry_rim(const unsigned char rim[MAX_MEASUREMENT_SIZE],
                      unsigned long rd_addr,
                      unsigned long pd_addr)
{
    unsigned int i;

    if (!rim) {
        return 0;
    }

    ram_lock(&ramlock);

    /* Enforce uniqueness: rd_addr, pd_addr, rim */
    for (i = 0; i < ram.count; i++) {
        if (ram.e[i].rd_addr == rd_addr) {
            ram_unlock(&ramlock);
            return 0; /* duplicate rd_addr */
        }
        if (ram.e[i].pd_addr == pd_addr) {
            ram_unlock(&ramlock);
            return 0; /* duplicate pd_addr */
        }
        if (memcmp(ram.e[i].rim, rim, MAX_MEASUREMENT_SIZE) == 0) {
            ram_unlock(&ramlock);
            return 0; /* duplicate rim */
        }
    }

    if (ram.count >= PARSER_MAX_VMS) {
        ram_unlock(&ramlock);
        return 0; /* table full */
    }

    ram.e[ram.count].has_hash = false;
    ram.e[ram.count].hash = 0UL;
    memcpy(ram.e[ram.count].rim, rim, MAX_MEASUREMENT_SIZE);
    ram.e[ram.count].rd_addr = rd_addr;
    ram.e[ram.count].pd_addr = pd_addr;
    ram.count++;

    ram_unlock(&ramlock);
    return 1;
}

int ram_add_hash_for_pd(unsigned long hash, unsigned long pd_addr)
{
    unsigned int i;
    int idx = -1;

    ram_lock(&ramlock);

    /* Find target entry by pd_addr */
    for (i = 0; i < ram.count; i++) {
        if (ram.e[i].pd_addr == pd_addr) {
            idx = (int)i;
            break;
        }
    }

    if (idx < 0) {
        ram_unlock(&ramlock);
        return 0; /* pd_addr not found */
    }

    /* Reject if already has a hash */
    if (ram.e[idx].has_hash) {
        ram_unlock(&ramlock);
        return 0;
    }

    /* Enforce global uniqueness: hash (among set hashes) */
    for (i = 0; i < ram.count; i++) {
        if (ram.e[i].has_hash && ram.e[i].hash == hash) {
            ram_unlock(&ramlock);
            return 0; /* duplicate hash */
        }
    }

    ram.e[idx].hash = hash;
    ram.e[idx].has_hash = true;

    ram_unlock(&ramlock);
    return 1;
}

static inline void ram_zero_out(type_rim_t *out)
{
    if (out) {
        memset(out, 0, sizeof(*out));
    }
}

int ram_get_entry_from_hash(unsigned long hash, type_rim_t *out)
{
    unsigned int i;
    int found = 0;

    ram_lock(&ramlock);

    for (i = 0; i < ram.count; i++) {
        if (ram.e[i].has_hash && ram.e[i].hash == hash) {
            if (out) {
                *out = ram.e[i];
            }
            found = 1;
            break;
        }
    }

    ram_unlock(&ramlock);

    if (!found) {
        ram_zero_out(out);
    }
    return found;
}

int ram_get_entry_from_rim(const unsigned char rim[MAX_MEASUREMENT_SIZE], type_rim_t *out)
{
    unsigned int i;
    int found = 0;

    if (!rim) {
        ram_zero_out(out);
        return 0;
    }

    ram_lock(&ramlock);

    for (i = 0; i < ram.count; i++) {
        if (memcmp(ram.e[i].rim, rim, MAX_MEASUREMENT_SIZE) == 0) {
            if (out) {
                *out = ram.e[i];
            }
            found = 1;
            break;
        }
    }

    ram_unlock(&ramlock);

    if (!found) {
        ram_zero_out(out);
    }
    return found;
}

int ram_get_entry_from_rd(unsigned long rd_addr, type_rim_t *out)
{
    unsigned int i;
    int found = 0;

    ram_lock(&ramlock);

    for (i = 0; i < ram.count; i++) {
        if (ram.e[i].rd_addr == rd_addr) {
            if (out) {
                *out = ram.e[i];
            }
            found = 1;
            break;
        }
    }

    ram_unlock(&ramlock);

    if (!found) {
        ram_zero_out(out);
    }
    return found;
}

int ram_get_entry_from_pd(unsigned long pd_addr, type_rim_t *out)
{
    unsigned int i;
    int found = 0;

    ram_lock(&ramlock);

    for (i = 0; i < ram.count; i++) {
        if (ram.e[i].pd_addr == pd_addr) {
            if (out) {
                *out = ram.e[i];
            }
            found = 1;
            break;
        }
    }

    ram_unlock(&ramlock);

    if (!found) {
        ram_zero_out(out);
    }
	return found;
}

int ram_remove_entry_from_rd(unsigned long rd_addr)
{
	unsigned int i;

	ram_lock(&ramlock);

	for (i = 0; i < ram.count; i++) {
		if (ram.e[i].rd_addr == rd_addr) {
			unsigned int last = ram.count - 1U;

			if (i != last) {
				ram.e[i] = ram.e[last];
			}
			memset(&ram.e[last], 0, sizeof(ram.e[last]));
			ram.count--;

			ram_unlock(&ramlock);
			return 1;
		}
	}

	ram_unlock(&ramlock);
	return 0;
}

int ram_remove_entry_from_pd(unsigned long pd_addr)
{
	unsigned int i;

	ram_lock(&ramlock);

	for (i = 0; i < ram.count; i++) {
		if (ram.e[i].pd_addr == pd_addr) {
			unsigned int last = ram.count - 1U;

			if (i != last) {
				ram.e[i] = ram.e[last];
			}
			memset(&ram.e[last], 0, sizeof(ram.e[last]));
			ram.count--;

			ram_unlock(&ramlock);
			return 1;
		}
	}

	ram_unlock(&ramlock);
	return 0;
}

unsigned int ram_scrub_stale_entries(void)
{
	unsigned int i = 0U;
	unsigned int removed = 0U;

	ram_lock(&ramlock);

	while (i < ram.count) {
		struct granule *g_rd = find_granule(ram.e[i].rd_addr);

		if ((g_rd != NULL) &&
		    (granule_unlocked_state(g_rd) == GRANULE_STATE_RD)) {
			i++;
			continue;
		}

		removed++;
		if (i != (ram.count - 1U)) {
			ram.e[i] = ram.e[ram.count - 1U];
		}
		memset(&ram.e[ram.count - 1U], 0, sizeof(ram.e[ram.count - 1U]));
		ram.count--;
	}

	ram_unlock(&ramlock);
	return removed;
}

void ram_pretty_print(void)
{
    unsigned int i, j;

    ram_lock(&ramlock);

    INFO("RAM: count=%u\n", ram.count);
    for (i = 0; i < ram.count; i++) {
        if (ram.e[i].has_hash) {
            INFO("  [%2u] hash=0x%lx rd_addr=0x%lx pd_addr=0x%lx rim=",
                 i, ram.e[i].hash, ram.e[i].rd_addr, ram.e[i].pd_addr);
        } else {
            INFO("  [%2u] hash=<unset> rd_addr=0x%lx pd_addr=0x%lx rim=",
                 i, ram.e[i].rd_addr, ram.e[i].pd_addr);
        }

        for (j = 0; j < MAX_MEASUREMENT_SIZE; j++) {
            INFO("%s%02x", (j ? ":" : ""), (unsigned int)ram.e[i].rim[j]);
        }
        INFO("\n");
    }

    ram_unlock(&ramlock);
}
