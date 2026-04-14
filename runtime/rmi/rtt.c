/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 */

#include <assert.h>
#include <buffer.h>
#include <errno.h>
#include <granule.h>
#include <measurement.h>
#include <realm.h>
#include <ripas.h>
#include <s2tt.h>
#include <smc-handler.h>
#include <smc-rmi.h>
#include <smc.h>
#include <status.h>
#include <stddef.h>
#include <string.h>
#include <private_shared_table.h>
// #include <realm_add_meta.h>
#include <rmi_rsi_count.h>
#include <psr_hpa_share_table.h>
// #include <policy_table.h>

#ifndef S2TT_MIN_DEV_BLOCK_LEVEL
#define S2TT_MIN_DEV_BLOCK_LEVEL S2TT_MIN_BLOCK_LEVEL
#endif

#ifndef s2tte_is_assigned_dev_empty
#define s2tte_is_assigned_dev_empty(_ctx, _s2tte, _lvl) \
	s2tte_is_assigned_empty((_ctx), (_s2tte), (_lvl))
#endif
#ifndef s2tt_init_assigned_dev_empty
#define s2tt_init_assigned_dev_empty(_ctx, _tbl, _pa, _lvl) \
	s2tt_init_assigned_empty((_ctx), (_tbl), (_pa), (_lvl))
#endif
#ifndef s2tte_is_assigned_dev_destroyed
#define s2tte_is_assigned_dev_destroyed(_ctx, _s2tte, _lvl) \
	s2tte_is_assigned_destroyed((_ctx), (_s2tte), (_lvl))
#endif
#ifndef s2tt_init_assigned_dev_destroyed
#define s2tt_init_assigned_dev_destroyed(_ctx, _tbl, _pa, _lvl) \
	s2tt_init_assigned_destroyed((_ctx), (_tbl), (_pa), (_lvl))
#endif
#ifndef s2tte_is_assigned_dev_dev
#define s2tte_is_assigned_dev_dev(_ctx, _s2tte, _lvl) false
#endif
#ifndef s2tt_init_assigned_dev_dev
#define s2tt_init_assigned_dev_dev(_ctx, _tbl, _parent, _pa, _lvl) \
	s2tt_init_assigned_destroyed((_ctx), (_tbl), (_pa), (_lvl))
#endif
#ifndef s2tt_maps_assigned_dev_empty_block
#define s2tt_maps_assigned_dev_empty_block(_ctx, _tbl, _lvl) \
	s2tt_maps_assigned_empty_block((_ctx), (_tbl), (_lvl))
#endif
#ifndef s2tte_create_assigned_dev_empty
#define s2tte_create_assigned_dev_empty(_ctx, _s2tte, _lvl) \
	s2tte_create_assigned_empty((_ctx), (_s2tte), (_lvl))
#endif
#ifndef s2tt_maps_assigned_dev_destroyed_block
#define s2tt_maps_assigned_dev_destroyed_block(_ctx, _tbl, _lvl) \
	s2tt_maps_assigned_destroyed_block((_ctx), (_tbl), (_lvl))
#endif
#ifndef s2tte_create_assigned_dev_destroyed
#define s2tte_create_assigned_dev_destroyed(_ctx, _s2tte, _lvl) \
	s2tte_create_assigned_destroyed((_ctx), (_s2tte), (_lvl))
#endif
#ifndef s2tt_maps_assigned_dev_dev_block
#define s2tt_maps_assigned_dev_dev_block(_ctx, _tbl, _lvl) false
#endif
#ifndef s2tte_create_assigned_dev_dev
#define s2tte_create_assigned_dev_dev(_ctx, _s2tte, _lvl) \
	s2tte_create_assigned_destroyed((_ctx), (_s2tte), (_lvl))
#endif


/* One-shot helper:
 * Collect all [gpa,size] for self, then check whether (gpa + 0x1000) appears
 * among the collected GPAs and is owned by self.
 */
// static inline bool gpa_is_in_psr_owned_by_self(const struct parsed_payload *cfg,
// 					       					   uint64_t gpa,
// 											   uint32_t *hashes,
// 											   int *num_hashes)
// {
// 	struct policy_gpa_size pairs[PARSER_MAX_PS * PARSER_MAX_MAPS];
// 	size_t n, i;
// 	if (num_hashes) *num_hashes = 0;
// 	INFO("gpa_is_in_psr_owned_by_self: cfg=%p, gpa=0x%lx\n", cfg, gpa);

// 	if (cfg == NULL) {
// 		return false;
// 	}

// 	n = policy_get_all_self_gpa_sizes_where_self_is_owner(cfg, pairs, POLICY_ARRAY_SIZE(pairs));

// 	for (i = 0; i < n; i++) {
// 		INFO("gpa_is_in_psr_owned_by_self: checking pair[%zu]: gpa=0x%lx size=0x%u\n",
// 		     i, pairs[i].gpa, pairs[i].size);
// 		uint64_t base = pairs[i].gpa;
// 		uint32_t sz = pairs[i].size;
// 		if (gpa >= base && gpa < (base + sz)) {
// 			INFO("gpa_is_in_psr_owned_by_self: MATCH found in pair[%zu]: gpa=0x%lx size=0x%u\n",
// 			     i, pairs[i].gpa, pairs[i].size);
// 			if (num_hashes) {
//                 *num_hashes = get_vm_hashes_for_gpa(cfg, gpa, hashes, PARSER_MAX_VMS);
//             }
// 			return true;
// 		}
// 	}
// 	return false;
// }

/* One-shot helper:
 * Collect all [gpa,size] for self, then check whether (gpa + 0x1000) appears
 * among the collected GPAs.
 */
// static inline bool gpa_is_in_psr(const struct parsed_payload *cfg,
// 					       uint64_t gpa)
// {
// 	struct policy_gpa_size pairs[PARSER_MAX_PS * PARSER_MAX_MAPS];
// 	size_t n, i;

// 	if (cfg == NULL) {
// 		return false;
// 	}

// 	n = policy_get_all_self_gpa_sizes(cfg, pairs, POLICY_ARRAY_SIZE(pairs));

// 	for (i = 0; i < n; i++) {
// 		uint64_t base = pairs[i].gpa;
// 		uint32_t sz = pairs[i].size;
// 		if (gpa >= base && gpa < (base + sz)) {
// 			return true;
// 		}
// 		// if (pairs[i].gpa == needle) {
// 		// 	return true;
// 		// }
// 	}
// 	return false;
// }

/* Return parsed_ps index if ipa lies within a self-mapped PS range.
 * Range is [base_gpa, base_gpa + ps->size).
 */
// static inline int get_psr_id_for_ipa_range(const struct parsed_payload *cfg,
// 					   uint64_t ipa)
// {
// 	uint16_t self;
// 	uint16_t ps_idx, m_idx;

// 	if (cfg == NULL) {
// 		return -1;
// 	}

// 	self = cfg->self_vm_index;

// 	for (ps_idx = 0; (ps_idx < cfg->num_ps) && (ps_idx < PARSER_MAX_PS); ps_idx++) {
// 		const struct parsed_ps *ps = &cfg->ps[ps_idx];
// 		uint64_t sz = (uint64_t)ps->size;

// 		for (m_idx = 0; (m_idx < ps->num_mappings) && (m_idx < PARSER_MAX_MAPS); m_idx++) {
// 			const struct parsed_mapping *pm = &ps->mappings[m_idx];
// 			uint64_t base = pm->gpa;

// 			if (pm->vm_index != self) {
// 				continue;
// 			}

// 			if (ipa >= base && ipa < (base + sz)) {
// 				return (int)ps_idx;
// 			}
// 		}
// 	}

// 	return -1;
// }

/*
 * Validate the map_addr value passed to
 * RMI_RTT_*, RMI_DATA_* and RMI_DEV_MEM_* commands.
 */
static bool validate_map_addr(unsigned long map_addr,
			      long level,
			      struct rd *rd)
{
	return ((map_addr < realm_ipa_size(rd)) &&
		s2tte_is_addr_lvl_aligned(&(rd->s2_ctx), map_addr, level));
}

/*
 * Structure commands can operate on all RTTs except for the root RTT so
 * the minimal valid level is the stage 2 starting level + 1.
 */
static bool validate_rtt_structure_cmds(unsigned long map_addr,
					long level,
					struct rd *rd)
{
	int min_level = realm_rtt_starting_level(rd) + 1;

	if ((level < min_level) || (level > S2TT_PAGE_LEVEL)) {
		return false;
	}
	return validate_map_addr(map_addr, level - 1L, rd);
}

/*
 * Map/Unmap commands can operate up to a level 1 block entry so min_level is
 * the smallest block size.
 */
static bool validate_rtt_map_cmds(unsigned long map_addr,
				  long level,
				  struct rd *rd)
{
	if ((level < S2TT_MIN_BLOCK_LEVEL) || (level > S2TT_PAGE_LEVEL)) {
		return false;
	}
	return validate_map_addr(map_addr, level, rd);
}

/*
 * Entry commands can operate on any entry so the minimal valid level is the
 * stage 2 starting level.
 */
static bool validate_rtt_entry_cmds(unsigned long map_addr,
				    long level,
				    struct rd *rd)
{
	if ((level < realm_rtt_starting_level(rd)) ||
	    (level > S2TT_PAGE_LEVEL)) {
		return false;
	}
	return validate_map_addr(map_addr, level, rd);
}

unsigned long smc_rtt_create(unsigned long rd_addr,
			     unsigned long rtt_addr,
			     unsigned long map_addr,
			     unsigned long ulevel)
{
	struct granule *g_rd;
	struct granule *g_tbl;
	struct rd *rd;
	struct s2tt_walk wi;
	unsigned long *s2tt, *parent_s2tt, parent_s2tte;
	long level = (long)ulevel;
	unsigned long ret;
	struct s2tt_context s2_ctx;

	if (!find_lock_two_granules(rtt_addr,
				    GRANULE_STATE_DELEGATED,
				    &g_tbl,
				    rd_addr,
				    GRANULE_STATE_RD,
				    &g_rd)) {
		return RMI_ERROR_INPUT;
	}

	rd = buffer_granule_map(g_rd, SLOT_RD);
	assert(rd != NULL);

	if (!validate_rtt_structure_cmds(map_addr, level, rd)) {
		buffer_unmap(rd);
		granule_unlock(g_rd);
		granule_unlock(g_tbl);
		return RMI_ERROR_INPUT;
	}

	s2_ctx = rd->s2_ctx;
	buffer_unmap(rd);

	/*
	 * If LPA2 is disabled for the realm, then `rtt_addr` must not be
	 * more than 48 bits wide.
	 */
	if (!s2_ctx.enable_lpa2) {
		if ((rtt_addr >= (UL(1) << S2TT_MAX_PA_BITS))) {
			granule_unlock(g_rd);
			granule_unlock(g_tbl);
			return RMI_ERROR_INPUT;
		}
	}

	/*
	 * Lock the RTT root. Enforcing locking order RD->RTT is enough to
	 * ensure deadlock free locking guarantee.
	 */
	granule_lock(s2_ctx.g_rtt, GRANULE_STATE_RTT);

	/* Unlock RD after locking RTT Root */
	granule_unlock(g_rd);

	s2tt_walk_lock_unlock(&s2_ctx, map_addr, level - 1L, &wi);
	if (wi.last_level != (level - 1L)) {
		ret = pack_return_code(RMI_ERROR_RTT,
					(unsigned char)wi.last_level);
		goto out_unlock_llt;
	}

	parent_s2tt = buffer_granule_map(wi.g_llt, SLOT_RTT);
	assert(parent_s2tt != NULL);

	parent_s2tte = s2tte_read(&parent_s2tt[wi.index]);
	s2tt = buffer_granule_map(g_tbl, SLOT_DELEGATED);
	assert(s2tt != NULL);

	if (s2tte_is_unassigned_empty(&s2_ctx, parent_s2tte)) {
		s2tt_init_unassigned_empty(&s2_ctx, s2tt);

		/*
		 * Atomically increase the refcount of the parent, the granule
		 * was locked while table walking and hand-over-hand locking.
		 * Acquire/release semantics not required because the table is
		 * accessed always locked.
		 */
		atomic_granule_get(wi.g_llt);

	} else if (s2tte_is_unassigned_ram(&s2_ctx, parent_s2tte)) {
		s2tt_init_unassigned_ram(&s2_ctx, s2tt);
		atomic_granule_get(wi.g_llt);

	} else if (s2tte_is_unassigned_ns(&s2_ctx, parent_s2tte)) {
		s2tt_init_unassigned_ns(&s2_ctx, s2tt);
		atomic_granule_get(wi.g_llt);

	} else if (s2tte_is_unassigned_destroyed(&s2_ctx, parent_s2tte)) {
		s2tt_init_unassigned_destroyed(&s2_ctx, s2tt);
		atomic_granule_get(wi.g_llt);

	} else if (s2tte_is_assigned_destroyed(&s2_ctx, parent_s2tte,
					       level - 1L)) {
		unsigned long block_pa;

		/*
		 * We should observe parent assigned s2tte only when
		 * we create tables above this level.
		 */
		assert(level > S2TT_MIN_BLOCK_LEVEL);

		block_pa = s2tte_pa(&s2_ctx, parent_s2tte, level - 1L);

		s2tt_init_assigned_destroyed(&s2_ctx, s2tt, block_pa, level);

		/*
		 * Increase the refcount to mark the granule as in-use. refcount
		 * is incremented by S2TTES_PER_S2TT (ref RTT unfolding).
		 */
		granule_refcount_inc(g_tbl, (unsigned short)S2TTES_PER_S2TT);

	} else if (s2tte_is_assigned_empty(&s2_ctx, parent_s2tte, level - 1L)) {
		unsigned long block_pa;

		/*
		 * We should observe parent assigned s2tte only when
		 * we create tables above this level.
		 */
		assert(level > S2TT_MIN_BLOCK_LEVEL);

		block_pa = s2tte_pa(&s2_ctx, parent_s2tte, level - 1L);

		s2tt_init_assigned_empty(&s2_ctx, s2tt, block_pa, level);

		/*
		 * Increase the refcount to mark the granule as in-use. refcount
		 * is incremented by S2TTES_PER_S2TT (ref RTT unfolding).
		 */
		granule_refcount_inc(g_tbl, (unsigned short)S2TTES_PER_S2TT);

	} else if (s2tte_is_assigned_ram(&s2_ctx, parent_s2tte, level - 1L)) {
		unsigned long block_pa;

		/*
		 * We should observe parent valid s2tte only when
		 * we create tables above this level.
		 */
		assert(level > S2TT_MIN_BLOCK_LEVEL);

		/*
		 * Break before make. This may cause spurious S2 aborts.
		 */
		s2tte_write(&parent_s2tt[wi.index], 0UL);
		s2tt_invalidate_block(&s2_ctx, map_addr);

		block_pa = s2tte_pa(&s2_ctx, parent_s2tte, level - 1L);

		s2tt_init_assigned_ram(&s2_ctx, s2tt, block_pa, level);

		/*
		 * Increase the refcount to mark the granule as in-use. refcount
		 * is incremented by S2TTES_PER_S2TT (ref RTT unfolding).
		 */
		granule_refcount_inc(g_tbl, (unsigned short)S2TTES_PER_S2TT);

	} else if (s2tte_is_assigned_ns(&s2_ctx, parent_s2tte, level - 1L)) {
		unsigned long block_pa;

		/*
		 * We should observe parent assigned_ns s2tte only when
		 * we create tables above this level.
		 */
		assert(level > S2TT_MIN_BLOCK_LEVEL);

		/*
		 * Break before make. This may cause spurious S2 aborts.
		 */
		s2tte_write(&parent_s2tt[wi.index], 0UL);
		s2tt_invalidate_block(&s2_ctx, map_addr);

		block_pa = s2tte_pa(&s2_ctx, parent_s2tte, level - 1L);

		s2tt_init_assigned_ns(&s2_ctx, s2tt, parent_s2tte,
				      block_pa, level);

		/*
		 * Increment the refcount on the parent for the new RTT we are
		 * about to add. The NS block entry doesn't have a refcount
		 * on the parent RTT.
		 */
		atomic_granule_get(wi.g_llt);

	} else if (s2tte_is_assigned_dev_empty(&s2_ctx, parent_s2tte, level - 1L)) {
		unsigned long block_pa;

		/*
		 * We should observe parent assigned s2tte only when
		 * we create tables above this level.
		 */
		assert(level > S2TT_MIN_DEV_BLOCK_LEVEL);

		block_pa = s2tte_pa(&s2_ctx, parent_s2tte, level - 1L);

		s2tt_init_assigned_dev_empty(&s2_ctx, s2tt, block_pa, level);

		/*
		 * Increase the refcount to mark the granule as in-use. refcount
		 * is incremented by S2TTES_PER_S2TT (ref RTT unfolding).
		 */
		granule_refcount_inc(g_tbl, (unsigned short)S2TTES_PER_S2TT);

	} else if (s2tte_is_assigned_dev_destroyed(&s2_ctx, parent_s2tte, level - 1L)) {
		unsigned long block_pa;

		/*
		 * We should observe parent assigned s2tte only when
		 * we create tables above this level.
		 */
		assert(level > S2TT_MIN_DEV_BLOCK_LEVEL);

		block_pa = s2tte_pa(&s2_ctx, parent_s2tte, level - 1L);

		s2tt_init_assigned_dev_destroyed(&s2_ctx, s2tt, block_pa, level);

		/*
		 * Increase the refcount to mark the granule as in-use. refcount
		 * is incremented by S2TTES_PER_S2TT (ref RTT unfolding).
		 */
		granule_refcount_inc(g_tbl, (unsigned short)S2TTES_PER_S2TT);

	} else if (s2tte_is_assigned_dev_dev(&s2_ctx, parent_s2tte, level - 1L)) {
		unsigned long block_pa;

		/*
		 * We should observe parent valid s2tte only when
		 * we create tables above this level.
		 */
		assert(level > S2TT_MIN_DEV_BLOCK_LEVEL);

		/*
		 * Break before make. This may cause spurious S2 aborts.
		 */
		s2tte_write(&parent_s2tt[wi.index], 0UL);
		s2tt_invalidate_block(&s2_ctx, map_addr);

		block_pa = s2tte_pa(&s2_ctx, parent_s2tte, level - 1L);

		s2tt_init_assigned_dev_dev(&s2_ctx, s2tt, parent_s2tte, block_pa, level);

		/*
		 * Increase the refcount to mark the granule as in-use. refcount
		 * is incremented by S2TTES_PER_S2TT (ref RTT unfolding).
		 */
		granule_refcount_inc(g_tbl, (unsigned short)S2TTES_PER_S2TT);

	} else if (s2tte_is_table(&s2_ctx, parent_s2tte, level - 1L)) {
		ret = pack_return_code(RMI_ERROR_RTT,
					(unsigned char)(level - 1L));
		goto out_unmap_table;

	} else {
		assert(false);
	}

	ret = RMI_SUCCESS;

	granule_set_state(g_tbl, GRANULE_STATE_RTT);

	parent_s2tte = s2tte_create_table(&s2_ctx, rtt_addr, level - 1L);
	s2tte_write(&parent_s2tt[wi.index], parent_s2tte);

out_unmap_table:
	buffer_unmap(s2tt);
	buffer_unmap(parent_s2tt);
out_unlock_llt:
	granule_unlock(wi.g_llt);
	granule_unlock(g_tbl);
	return ret;
}

void smc_rtt_fold(unsigned long rd_addr,
		  unsigned long map_addr,
		  unsigned long ulevel,
		  struct smc_result *res)
{
	struct granule *g_rd;
	struct granule *g_tbl;
	struct rd *rd;
	struct s2tt_walk wi;
	unsigned long *table, *parent_s2tt, parent_s2tte;
	long level = (long)ulevel;
	unsigned long rtt_addr;
	unsigned long ret;
	struct s2tt_context s2_ctx;

	g_rd = find_lock_granule(rd_addr, GRANULE_STATE_RD);
	if (g_rd == NULL) {
		res->x[0] = RMI_ERROR_INPUT;
		return;
	}

	rd = buffer_granule_map(g_rd, SLOT_RD);
	assert(rd != NULL);

	if (!validate_rtt_structure_cmds(map_addr, level, rd)) {
		buffer_unmap(rd);
		granule_unlock(g_rd);
		res->x[0] = RMI_ERROR_INPUT;
		return;
	}

	s2_ctx = rd->s2_ctx;
	buffer_unmap(rd);
	granule_lock(s2_ctx.g_rtt, GRANULE_STATE_RTT);
	granule_unlock(g_rd);

	s2tt_walk_lock_unlock(&s2_ctx, map_addr, level - 1L, &wi);
	if (wi.last_level != (level - 1L)) {
		ret = pack_return_code(RMI_ERROR_RTT,
					(unsigned char)wi.last_level);
		goto out_unlock_parent_table;
	}

	parent_s2tt = buffer_granule_map(wi.g_llt, SLOT_RTT);
	assert(parent_s2tt != NULL);

	parent_s2tte = s2tte_read(&parent_s2tt[wi.index]);
	if (!s2tte_is_table(&s2_ctx, parent_s2tte, level - 1L)) {
		ret = pack_return_code(RMI_ERROR_RTT,
					(unsigned char)(level - 1L));
		goto out_unmap_parent_table;
	}

	rtt_addr = s2tte_pa(&s2_ctx, parent_s2tte, level - 1L);
	g_tbl = find_lock_granule(rtt_addr, GRANULE_STATE_RTT);

	/*
	 * A table descriptor S2TTE always points to a TABLE granule.
	 */
	assert(g_tbl != NULL);

	table = buffer_granule_map(g_tbl, SLOT_RTT2);
	assert(table != NULL);

	/*
	 * The command can succeed only if all 512 S2TTEs are of the same type.
	 * We first check the table's ref. counter to speed up the case when
	 * the host makes a guess whether a memory region can be folded.
	 */
	if (granule_refcount_read(g_tbl) == 0U) {
		if (s2tt_is_unassigned_destroyed_block(&s2_ctx, table)) {
			parent_s2tte = s2tte_create_unassigned_destroyed(&s2_ctx);
		} else if (s2tt_is_unassigned_empty_block(&s2_ctx, table)) {
			parent_s2tte = s2tte_create_unassigned_empty(&s2_ctx);
		} else if (s2tt_is_unassigned_ram_block(&s2_ctx, table)) {
			parent_s2tte = s2tte_create_unassigned_ram(&s2_ctx);
		} else if (s2tt_is_unassigned_ns_block(&s2_ctx, table)) {
			parent_s2tte = s2tte_create_unassigned_ns(&s2_ctx);
		} else if (s2tt_maps_assigned_ns_block(&s2_ctx, table, level)) {

			/*
			 * The RMM specification does not allow creating block entries less than
			 * S2TT_MIN_BLOCK_LEVEL for ASSIGNED_NS state.
			 */
			if (level <= S2TT_MIN_BLOCK_LEVEL) {
				ret = pack_return_code(RMI_ERROR_RTT,
						(unsigned char)wi.last_level);
				goto out_unmap_table;
			}
			unsigned long s2tte = s2tte_read(&table[0]);

			/*
			 * Since s2tt_maps_assigned_ns_block() has succedded,
			 * the PA in first entry of the table is aligned at
			 * parent level. Use the TTE from the first entry
			 * directly as it also has the NS attributes to be used
			 * for the parent block entry.
			 */
			parent_s2tte = s2tte_create_assigned_ns(&s2_ctx, s2tte, level - 1L);
		} else {
			/*
			 * The table holds a mixture of destroyed and
			 * unassigned entries.
			 */
			ret = pack_return_code(RMI_ERROR_RTT,
						(unsigned char)level);
			goto out_unmap_table;
		}
		atomic_granule_put(wi.g_llt);
	} else if (granule_refcount_read(g_tbl) ==
					(unsigned short)S2TTES_PER_S2TT) {

		unsigned long s2tte, block_pa;

		/* The RMM specification does not allow creating block
		 * entries less than S2TT_MIN_BLOCK_LEVEL even though
		 * permitted by the Arm Architecture.
		 * Hence ensure that the table being folded is at a level
		 * higher than the S2TT_MIN_BLOCK_LEVEL.
		 *
		 * A fully populated table cannot be destroyed if that
		 * would create a block mapping below S2TT_MIN_BLOCK_LEVEL.
		 */
		if (level <= S2TT_MIN_BLOCK_LEVEL) {
			ret = pack_return_code(RMI_ERROR_RTT,
						(unsigned char)wi.last_level);
			goto out_unmap_table;
		}

		s2tte = s2tte_read(&table[0]);
		block_pa = s2tte_pa(&s2_ctx, s2tte, level);

		/*
		 * The table must also refer to a contiguous block through the
		 * same type of s2tte, either Assigned or Valid.
		 */
		if (s2tt_maps_assigned_empty_block(&s2_ctx, table, level)) {
			parent_s2tte = s2tte_create_assigned_empty(&s2_ctx,
					block_pa, level - 1L);
		} else if (s2tt_maps_assigned_ram_block(&s2_ctx,
							table, level)) {
			parent_s2tte = s2tte_create_assigned_ram(&s2_ctx,
								 block_pa,
								 level - 1L);
		} else if (s2tt_maps_assigned_destroyed_block(&s2_ctx,
							      table, level)) {
			parent_s2tte = s2tte_create_assigned_destroyed(&s2_ctx,
							block_pa, level - 1L);
		} else if (s2tt_maps_assigned_dev_empty_block(&s2_ctx,
								table, level)) {
			parent_s2tte = s2tte_create_assigned_dev_empty(&s2_ctx,
									block_pa,
									level - 1L);
		} else if (s2tt_maps_assigned_dev_destroyed_block(&s2_ctx,
								  table, level)) {
			parent_s2tte = s2tte_create_assigned_dev_destroyed(&s2_ctx,
									   block_pa,
									   level - 1L);
		} else if (s2tt_maps_assigned_dev_dev_block(&s2_ctx, table, level)) {
			parent_s2tte = s2tte_create_assigned_dev_dev(&s2_ctx,
									s2tte,
									level - 1L);

		/* The table contains mixed entries that cannot be folded */
		} else {
			ret = pack_return_code(RMI_ERROR_RTT,
						(unsigned char)level);
			goto out_unmap_table;
		}

		granule_refcount_dec(g_tbl, (unsigned short)S2TTES_PER_S2TT);
	} else {
		/*
		 * The table holds a mixture of different types of s2ttes.
		 */
		ret = pack_return_code(RMI_ERROR_RTT,
					(unsigned char)level);
		goto out_unmap_table;
	}

	ret = RMI_SUCCESS;
	res->x[1] = rtt_addr;

	/*
	 * Break before make.
	 */
	s2tte_write(&parent_s2tt[wi.index], 0UL);

	if (s2tte_is_assigned_ram(&s2_ctx, parent_s2tte, level - 1L) ||
	    s2tte_is_assigned_ns(&s2_ctx, parent_s2tte, level - 1L)  ||
	    s2tte_is_assigned_dev_dev(&s2_ctx, parent_s2tte, level - 1L)) {
		s2tt_invalidate_pages_in_block(&s2_ctx, map_addr);
	} else {
		s2tt_invalidate_block(&s2_ctx, map_addr);
	}

	s2tte_write(&parent_s2tt[wi.index], parent_s2tte);

	granule_memzero_mapped(table);
	granule_set_state(g_tbl, GRANULE_STATE_DELEGATED);

out_unmap_table:
	buffer_unmap(table);
	granule_unlock(g_tbl);
out_unmap_parent_table:
	buffer_unmap(parent_s2tt);
out_unlock_parent_table:
	granule_unlock(wi.g_llt);
	res->x[0] = ret;
}

void smc_rtt_destroy(unsigned long rd_addr,
		     unsigned long map_addr,
		     unsigned long ulevel,
		     struct smc_result *res)
{
	struct granule *g_rd;
	struct granule *g_tbl;
	struct rd *rd;
	struct s2tt_walk wi;
	unsigned long *table, *parent_s2tt, parent_s2tte;
	long level = (long)ulevel;
	unsigned long  rtt_addr;
	unsigned long ret;
	struct s2tt_context s2_ctx;
	bool in_par, skip_non_live = false;

	g_rd = find_lock_granule(rd_addr, GRANULE_STATE_RD);
	if (g_rd == NULL) {
		res->x[0] = RMI_ERROR_INPUT;
		res->x[2] = 0UL;
		return;
	}

	rd = buffer_granule_map(g_rd, SLOT_RD);
	assert(rd != NULL);

	if (!validate_rtt_structure_cmds(map_addr, level, rd)) {
		INFO("rtt_destroy: invalid map_addr=%lx level=%ld\n",
		     map_addr, level);
		buffer_unmap(rd);
		granule_unlock(g_rd);
		res->x[0] = RMI_ERROR_INPUT;
		res->x[2] = 0UL;
		return;
	}

	s2_ctx = rd->s2_ctx;
	in_par = addr_in_par(rd, map_addr);
	buffer_unmap(rd);
	granule_lock(s2_ctx.g_rtt, GRANULE_STATE_RTT);
	granule_unlock(g_rd);

	s2tt_walk_lock_unlock(&s2_ctx, map_addr, level - 1L, &wi);

	parent_s2tt = buffer_granule_map(wi.g_llt, SLOT_RTT);
	assert(parent_s2tt != NULL);

	parent_s2tte = s2tte_read(&parent_s2tt[wi.index]);

	if ((wi.last_level != (level - 1L)) ||
	    !s2tte_is_table(&s2_ctx, parent_s2tte, level - 1L)) {
		ret = pack_return_code(RMI_ERROR_RTT,
					(unsigned char)wi.last_level);
		skip_non_live = true;
		INFO("rtt_destroy: invalid last_level=%ld expected=%ld\n",
		     wi.last_level, level - 1L);
		goto out_unmap_parent_table;
	}

	rtt_addr = s2tte_pa(&s2_ctx, parent_s2tte, level - 1L);

	/*
	 * Lock the RTT granule. The 'rtt_addr' is verified, thus can be treated
	 * as an internal granule.
	 */
	g_tbl = find_lock_granule(rtt_addr, GRANULE_STATE_RTT);

	/*
	 * A table descriptor S2TTE always points to a TABLE granule.
	 */
	assert(g_tbl != NULL);

	/*
	 * Read the refcount value. RTT granule is always accessed locked, thus
	 * the refcount can be accessed without atomic operations.
	 */
	if (granule_refcount_read(g_tbl) != 0U) {
		ret = pack_return_code(RMI_ERROR_RTT, (unsigned char)level);
		INFO("rtt_destroy: refcount!=0 refcount=%u\n",
		     granule_refcount_read(g_tbl));
		goto out_unlock_table;
	}

	ret = RMI_SUCCESS;
	res->x[1] = rtt_addr;
	skip_non_live = true;

	table = buffer_granule_map(g_tbl, SLOT_RTT2);
	assert(table != NULL);

	if (in_par) {
		parent_s2tte = s2tte_create_unassigned_destroyed(&s2_ctx);
	} else {
		parent_s2tte = s2tte_create_unassigned_ns(&s2_ctx);
	}

	atomic_granule_put(wi.g_llt);

	/*
	 * Break before make. Note that this may cause spurious S2 aborts.
	 */
	s2tte_write(&parent_s2tt[wi.index], 0UL);

	if (in_par) {
		/* For protected IPA, all S2TTEs in the RTT will be invalid */
		s2tt_invalidate_block(&s2_ctx, map_addr);
	} else {
		/*
		 * For unprotected IPA, invalidate the TLB for the entire range
		 * mapped by the RTT as it may have valid NS mappings.
		 */
		s2tt_invalidate_pages_in_block(&s2_ctx, map_addr);
	}

	s2tte_write(&parent_s2tt[wi.index], parent_s2tte);

	granule_memzero_mapped(table);
	granule_set_state(g_tbl, GRANULE_STATE_DELEGATED);

	buffer_unmap(table);
out_unlock_table:
	granule_unlock(g_tbl);
out_unmap_parent_table:
	if (skip_non_live) {
		res->x[2] = s2tt_skip_non_live_entries(&s2_ctx, map_addr,
						       parent_s2tt, &wi);
	} else {
		res->x[2] = map_addr;
	}
	buffer_unmap(parent_s2tt);
	granule_unlock(wi.g_llt);
	res->x[0] = ret;
}

enum map_unmap_ns_op {
	MAP_NS,
	UNMAP_NS
};

/*
 * We don't hold a reference on the NS granule when it is
 * mapped into a realm. Instead we rely on the guarantees
 * provided by the architecture to ensure that a NS access
 * to a protected granule is prohibited even within the realm.
 */
static void map_unmap_ns(unsigned long rd_addr,
			  unsigned long map_addr,
			  long level,
			  unsigned long host_s2tte,
			  enum map_unmap_ns_op op,
			  struct smc_result *res)
{
	struct granule *g_rd;
	struct rd *rd;
	unsigned long *s2tt, s2tte;
	struct s2tt_walk wi;
	struct s2tt_context s2_ctx;

	g_rd = find_lock_granule(rd_addr, GRANULE_STATE_RD);
	if (g_rd == NULL) {
		res->x[0] = RMI_ERROR_INPUT;
		return;
	}

	rd = buffer_granule_map(g_rd, SLOT_RD);
	assert(rd != NULL);

	if (op == MAP_NS) {
		struct parsed_payload cfg;
		if (load_cfg(rd->pd, &cfg, GRANULE_STATE_DELEGATED, SLOT_RSI_CALL)) {
			if (cfg.self_vm_index < cfg.num_vms &&
			    !cfg.vms[cfg.self_vm_index].is_gateway) {
				INFO("map_unmap_ns: MAP_NS rejected (sealed_mappings=1) "
					"rd=0x%lx ipa=0x%lx level=%ld\n",
					rd_addr, map_addr, level);
				buffer_unmap(rd);
				granule_unlock(g_rd);
				res->x[0] = RMI_ERROR_INPUT;
				return;
			}
		}
	}

	// unsigned long pd_addr = rd->pd;

	// struct parsed_payload cfg;
	// load_cfg(pd_addr, &cfg);

	/* NEW: block MAP_NS if Realm has been sealed - this will be replaced with policy check*/
	// if (op == MAP_NS && rd->sealed_mappings == true) {
	// 	INFO("map_unmap_ns: MAP_NS rejected (sealed_mappings=1) "
	// 	     "rd=0x%lx ipa=0x%lx level=%ld\n",
	// 	     rd_addr, map_addr, level);
	// 	buffer_unmap(rd);
	// 	granule_unlock(g_rd);
	// 	res->x[0] = RMI_ERROR_INPUT; /* or RMI_ERROR_RTT / REALM, your choice */
	// 	return;
	// }

	// if (op == MAP_NS && gpa_is_in_psr(&cfg, map_addr)) {
	// 	INFO("map_unmap_ns: MAP_NS rejected (PSR overlap) "
	// 	     "rd=0x%lx ipa=0x%lx\n",
	// 	     rd_addr, map_addr);
	// 	buffer_unmap(rd);
	// 	granule_unlock(g_rd);
	// 	res->x[0] = RMI_ERROR_INPUT;
	// 	return;
	// }

	s2_ctx = rd->s2_ctx;

	if (op == MAP_NS) {
		if (!host_ns_s2tte_is_valid(&s2_ctx, host_s2tte, level)) {
			buffer_unmap(rd);
			granule_unlock(g_rd);
			res->x[0] = RMI_ERROR_INPUT;
			return;
		}
	}


	if (!validate_rtt_map_cmds(map_addr, level, rd)) {
		buffer_unmap(rd);
		granule_unlock(g_rd);
		res->x[0] = RMI_ERROR_INPUT;
		return;
	}

	/* Check if map_addr is outside PAR */
	if (addr_in_par(rd, map_addr)) {
		buffer_unmap(rd);
		granule_unlock(g_rd);
		res->x[0] = RMI_ERROR_INPUT;
		return;
	}

	buffer_unmap(rd);
	granule_lock(s2_ctx.g_rtt, GRANULE_STATE_RTT);
	granule_unlock(g_rd);

	s2tt_walk_lock_unlock(&s2_ctx, map_addr, level, &wi);

	/*
	 * For UNMAP_NS, we need to map the table and look
	 * for the end of the non-live region.
	 */
	if ((op == MAP_NS) && (wi.last_level != level)) {
		res->x[0] = pack_return_code(RMI_ERROR_RTT,
						(unsigned char)wi.last_level);
		goto out_unlock_llt;
	}

	s2tt = buffer_granule_map(wi.g_llt, SLOT_RTT);
	assert(s2tt != NULL);

	s2tte = s2tte_read(&s2tt[wi.index]);

	if (op == MAP_NS) {
		if (!s2tte_is_unassigned_ns(&s2_ctx, s2tte)) {
			res->x[0] = pack_return_code(RMI_ERROR_RTT,
						(unsigned char)level);
			goto out_unmap_table;
		}

		s2tte = s2tte_create_assigned_ns(&s2_ctx, host_s2tte, level);
		s2tte_write(&s2tt[wi.index], s2tte);

	} else if (op == UNMAP_NS) {
		/*
		 * The following check also verifies that map_addr is outside
		 * PAR, as valid_NS s2tte may only cover outside PAR IPA range.
		 */

		bool assigned_ns = s2tte_is_assigned_ns(&s2_ctx, s2tte,
							wi.last_level);

		if ((wi.last_level != level) || !assigned_ns) {
			res->x[0] = pack_return_code(RMI_ERROR_RTT,
						(unsigned char)wi.last_level);
			goto out_unmap_table;
		}

		s2tte = s2tte_create_unassigned_ns(&s2_ctx);
		s2tte_write(&s2tt[wi.index], s2tte);
		if (level == S2TT_PAGE_LEVEL) {
			s2tt_invalidate_page(&s2_ctx, map_addr);
		} else {
			s2tt_invalidate_block(&s2_ctx, map_addr);
		}
	}

	res->x[0] = RMI_SUCCESS;

out_unmap_table:
	if (op == UNMAP_NS) {
		res->x[1] = s2tt_skip_non_live_entries(&s2_ctx, map_addr,
						       s2tt, &wi);
	}
	buffer_unmap(s2tt);
out_unlock_llt:
	granule_unlock(wi.g_llt);
}

unsigned long smc_rtt_map_unprotected(unsigned long rd_addr,
				      unsigned long map_addr,
				      unsigned long ulevel,
				      unsigned long s2tte)
{
	long level = (long)ulevel;
	struct smc_result res;

	(void)memset(&res, 0, sizeof(struct smc_result));
	if ((level < S2TT_MIN_BLOCK_LEVEL) || (level > S2TT_PAGE_LEVEL)) {
		return RMI_ERROR_INPUT;
	}

	map_unmap_ns(rd_addr, map_addr, level, s2tte, MAP_NS, &res);
	
	//rrt_pretty_print();
	return res.x[0];
}

void smc_rtt_unmap_unprotected(unsigned long rd_addr,
				unsigned long map_addr,
				unsigned long ulevel,
				struct smc_result *res)
{
	// struct granule *g_rd;
	// struct rd *rd;
	long level = (long)ulevel;

	if ((level < S2TT_MIN_BLOCK_LEVEL) || (level > S2TT_PAGE_LEVEL)) {
		res->x[0] = RMI_ERROR_INPUT;
		return;
	}

	map_unmap_ns(rd_addr, map_addr, level, 0UL, UNMAP_NS, res);
}

void smc_rtt_read_entry(unsigned long rd_addr,
			unsigned long map_addr,
			unsigned long ulevel,
			struct smc_result *res)
{
	struct granule *g_rd;
	struct rd *rd;
	struct s2tt_walk wi;
	unsigned long *s2tt, s2tte;
	long level = (long)ulevel;
	struct s2tt_context s2_ctx;

	g_rd = find_lock_granule(rd_addr, GRANULE_STATE_RD);
	if (g_rd == NULL) {
		res->x[0] = RMI_ERROR_INPUT;
		return;
	}

	rd = buffer_granule_map(g_rd, SLOT_RD);
	assert(rd != NULL);

	if (!validate_rtt_entry_cmds(map_addr, level, rd)) {
		buffer_unmap(rd);
		granule_unlock(g_rd);
		res->x[0] = RMI_ERROR_INPUT;
		return;
	}

	s2_ctx = rd->s2_ctx;
	buffer_unmap(rd);

	granule_lock(s2_ctx.g_rtt, GRANULE_STATE_RTT);
	granule_unlock(g_rd);

	s2tt_walk_lock_unlock(&s2_ctx, map_addr, level, &wi);
	s2tt = buffer_granule_map(wi.g_llt, SLOT_RTT);
	assert(s2tt != NULL);

	s2tte = s2tte_read(&s2tt[wi.index]);
	res->x[1] = (unsigned long)wi.last_level;

	if (s2tte_is_unassigned_empty(&s2_ctx, s2tte)) {
		res->x[2] = RMI_UNASSIGNED;
		res->x[3] = 0UL;
		res->x[4] = (unsigned long)RIPAS_EMPTY;
	} else if (s2tte_is_unassigned_ram(&s2_ctx, s2tte)) {
		res->x[2] = RMI_UNASSIGNED;
		res->x[3] = 0UL;
		res->x[4] = (unsigned long)RIPAS_RAM;
	} else if (s2tte_is_unassigned_destroyed(&s2_ctx, s2tte)) {
		res->x[2] = RMI_UNASSIGNED;
		res->x[3] = 0UL;
		res->x[4] = (unsigned long)RIPAS_DESTROYED;
	} else if (s2tte_is_assigned_empty(&s2_ctx, s2tte, wi.last_level)) {
		res->x[2] = RMI_ASSIGNED;
		res->x[3] = s2tte_pa(&s2_ctx, s2tte, wi.last_level);
		res->x[4] = (unsigned long)RIPAS_EMPTY;
	} else if (s2tte_is_assigned_ram(&s2_ctx, s2tte, wi.last_level)) {
		res->x[2] = RMI_ASSIGNED;
		res->x[3] = s2tte_pa(&s2_ctx, s2tte, wi.last_level);
		res->x[4] = (unsigned long)RIPAS_RAM;
	} else if (s2tte_is_assigned_destroyed(&s2_ctx, s2tte, wi.last_level)) {
		res->x[2] = RMI_ASSIGNED;
		res->x[3] = s2tte_pa(&s2_ctx, s2tte, wi.last_level);
		res->x[4] = (unsigned long)RIPAS_DESTROYED;
	} else if (s2tte_is_assigned_dev_empty(&s2_ctx, s2tte, wi.last_level)) {
		res->x[2] = RMI_ASSIGNED_DEV;
		res->x[3] = s2tte_pa(&s2_ctx, s2tte, wi.last_level);
		res->x[4] = (unsigned long)RIPAS_EMPTY;
	} else if (s2tte_is_assigned_dev_destroyed(&s2_ctx, s2tte,
							wi.last_level)) {
		res->x[2] = RMI_ASSIGNED_DEV;
		res->x[3] = 0UL;
		res->x[4] = (unsigned long)RIPAS_DESTROYED;
	} else if (s2tte_is_assigned_dev_dev(&s2_ctx, s2tte, wi.last_level)) {
		res->x[2] = RMI_ASSIGNED_DEV;
		res->x[3] = s2tte_pa(&s2_ctx, s2tte, wi.last_level);
		res->x[4] = (unsigned long)RIPAS_DEV;
	} else if (s2tte_is_unassigned_ns(&s2_ctx, s2tte)) {
		res->x[2] = RMI_UNASSIGNED;
		res->x[3] = 0UL;
		res->x[4] = (unsigned long)RIPAS_EMPTY;
	} else if (s2tte_is_assigned_ns(&s2_ctx, s2tte, wi.last_level)) {
		res->x[2] = RMI_ASSIGNED;
		res->x[3] = host_ns_s2tte(&s2_ctx, s2tte, wi.last_level);
		res->x[4] = (unsigned long)RIPAS_EMPTY;
	} else if (s2tte_is_table(&s2_ctx, s2tte, wi.last_level)) {
		res->x[2] = RMI_TABLE;
		res->x[3] = s2tte_pa(&s2_ctx, s2tte, wi.last_level);
		res->x[4] = (unsigned long)RIPAS_EMPTY;
	} else {
		assert(false);
	}

	buffer_unmap(s2tt);
	granule_unlock(wi.g_llt);

	res->x[0] = RMI_SUCCESS;
}

static unsigned long validate_data_create_unknown(unsigned long map_addr,
						  struct rd *rd)
{
	if (!addr_in_par(rd, map_addr)) {
		return RMI_ERROR_INPUT;
	}

	if (!validate_map_addr(map_addr, S2TT_PAGE_LEVEL, rd)) {
		return RMI_ERROR_INPUT;
	}

	return RMI_SUCCESS;
}

// static unsigned long validate_data_create_unknown_shared(unsigned long map_addr,
// 						  struct rd *rd)
// {
// 	//check if the address is in shared..other RMI later

// 	if (!validate_map_addr(map_addr, S2TT_PAGE_LEVEL, rd)) {
// 		return RMI_ERROR_INPUT;
// 	}

// 	return RMI_SUCCESS;
// }

static unsigned long validate_data_create(unsigned long map_addr,
					  struct rd *rd)
{
	if (get_rd_state_locked(rd) != REALM_NEW) {
		return RMI_ERROR_REALM;
	}

	return validate_data_create_unknown(map_addr, rd);
}

/*
 * Implements both RMI_DATA_CREATE and RMI_DATA_CREATE_UNKNOWN
 *
 * if @g_src == NULL, implements RMI_DATA_CREATE_UNKNOWN
 * and RMI_DATA_CREATE otherwise.
 */
static unsigned long data_create(unsigned long rd_addr,
				 unsigned long data_addr,
				 unsigned long map_addr,
				 struct granule *g_src,
				 unsigned long flags)
{
	struct granule *g_data;
	struct granule *g_rd;
	struct rd *rd;
	struct s2tt_walk wi;
	struct s2tt_context *s2_ctx;
	unsigned long s2tte, *s2tt;
	unsigned char new_data_state = GRANULE_STATE_DELEGATED;
	unsigned long ret;

	if (!find_lock_two_granules(data_addr,
				    GRANULE_STATE_DELEGATED,
				    &g_data,
				    rd_addr,
				    GRANULE_STATE_RD,
				    &g_rd)) {
		return RMI_ERROR_INPUT;
	}

	rd = buffer_granule_map(g_rd, SLOT_RD);
	assert(rd != NULL);

	// unsigned long pd_addr = rd->pd;

	// struct parsed_payload cfg;
	// load_cfg(pd_addr, &cfg);

	// if(rd->sealed_mappings) {
	// 	INFO("data_create: RMI_DATA_CREATE rejected (realm sealed) "
	// 	     "rd=0x%lx data=0x%lx map=0x%lx\n",
	// 	     rd_addr, data_addr, map_addr);
	// 	ret = RMI_ERROR_INPUT;
	// 	goto out_unmap_rd;
	// }
	//I can't block data_create if realm is sealed, because this would require heavy kernel mods.

	// if (gpa_is_in_psr(&cfg, map_addr)) {
	// 	INFO("data_create: MAP_NS rejected (PSR overlap) "
	// 	     "rd=0x%lx ipa=0x%lx\n",
	// 	     rd_addr, map_addr);
	// 	ret = RMI_ERROR_INPUT;
	// 	goto out_unmap_rd;
	// }

	ret = (g_src != NULL) ?
		validate_data_create(map_addr, rd) :
		validate_data_create_unknown(map_addr, rd);

	if (ret != RMI_SUCCESS) {
		goto out_unmap_rd;
	}

	s2_ctx = &(rd->s2_ctx);

	/*
	 * If LPA2 is disabled for the realm, then `data_addr` must not be
	 * more than 48 bits wide.
	 */
	if (!s2_ctx->enable_lpa2) {
		if ((data_addr >= (UL(1) << S2TT_MAX_PA_BITS))) {
			ret = RMI_ERROR_INPUT;
			goto out_unmap_rd;
		}
	}

	granule_lock(s2_ctx->g_rtt, GRANULE_STATE_RTT);

	s2tt_walk_lock_unlock(s2_ctx, map_addr, S2TT_PAGE_LEVEL, &wi);
	if (wi.last_level != S2TT_PAGE_LEVEL) {
		ret = pack_return_code(RMI_ERROR_RTT,
					(unsigned char)wi.last_level);
		goto out_unlock_ll_table;
	}

	s2tt = buffer_granule_map(wi.g_llt, SLOT_RTT);
	assert(s2tt != NULL);

	s2tte = s2tte_read(&s2tt[wi.index]);
	if (!s2tte_is_unassigned(s2_ctx, s2tte)) {
		ret = pack_return_code(RMI_ERROR_RTT,
					(unsigned char)S2TT_PAGE_LEVEL);
		goto out_unmap_ll_table;
	}

	if (g_src != NULL) {
		bool ns_access_ok;
		void *data = buffer_granule_map(g_data, SLOT_DELEGATED);

		assert(data != NULL);

		ns_access_ok = ns_buffer_read(SLOT_NS, g_src, 0U,
					      GRANULE_SIZE, data);
		if (!ns_access_ok) {
			/*
			 * Some data may be copied before the failure. Zero
			 * g_data granule as it will remain in delegated state.
			 */
			granule_memzero_mapped(data);
			buffer_unmap(data);
			ret = RMI_ERROR_INPUT;
			goto out_unmap_ll_table;
		}

		measurement_data_granule_measure(
			rd->measurement[RIM_MEASUREMENT_SLOT],
			rd->algorithm,
			data,
			map_addr,
			flags);
		buffer_unmap(data);

		s2tte = s2tte_create_assigned_ram(s2_ctx, data_addr,
						  S2TT_PAGE_LEVEL);
	} else {
		s2tte = s2tte_create_assigned_unchanged(s2_ctx, s2tte,
							data_addr,
							S2TT_PAGE_LEVEL);
	}

	new_data_state = GRANULE_STATE_DATA;

	s2tte_write(&s2tt[wi.index], s2tte);
	atomic_granule_get(wi.g_llt);

	ret = RMI_SUCCESS;

out_unmap_ll_table:
	buffer_unmap(s2tt);
out_unlock_ll_table:
	granule_unlock(wi.g_llt);
out_unmap_rd:
	buffer_unmap(rd);
	granule_unlock(g_rd);
	granule_unlock_transition(g_data, new_data_state);
	return ret;
}

// static unsigned long data_create_unknown_shared(unsigned long rd_addr,
// 				 unsigned long data_addr,
// 				 unsigned long map_addr)
// {
// 	struct granule *g_data;
// 	struct granule *g_rd;
// 	struct rd *rd;
// 	struct s2tt_walk wi;
// 	struct s2tt_context *s2_ctx;
// 	unsigned long s2tte, *s2tt;
// 	unsigned char new_data_state = GRANULE_STATE_DELEGATED;
// 	unsigned long ret;

// 	if (!find_lock_two_granules(data_addr,
// 				    GRANULE_STATE_DELEGATED,
// 				    &g_data,
// 				    rd_addr,
// 				    GRANULE_STATE_RD,
// 				    &g_rd)) {
// 		return RMI_ERROR_INPUT;
// 	}

// 	rd = buffer_granule_map(g_rd, SLOT_RD);
// 	assert(rd != NULL);

// 	ret = validate_data_create_unknown_shared(map_addr, rd);
	

// 	if (ret != RMI_SUCCESS) {
// 		goto out_unmap_rd;
// 	}

// 	s2_ctx = &(rd->s2_ctx);

// 	/*
// 	 * If LPA2 is disabled for the realm, then `data_addr` must not be
// 	 * more than 48 bits wide.
// 	 */
// 	if (!s2_ctx->enable_lpa2) {
// 		if ((data_addr >= (UL(1) << S2TT_MAX_PA_BITS))) {
// 			ret = RMI_ERROR_INPUT;
// 			goto out_unmap_rd;
// 		}
// 	}

// 	granule_lock(s2_ctx->g_rtt, GRANULE_STATE_RTT);

// 	s2tt_walk_lock_unlock(s2_ctx, map_addr, S2TT_PAGE_LEVEL, &wi);
// 	if (wi.last_level != S2TT_PAGE_LEVEL) {
// 		ret = pack_return_code(RMI_ERROR_RTT,
// 					(unsigned char)wi.last_level);
// 		goto out_unlock_ll_table;
// 	}

// 	s2tt = buffer_granule_map(wi.g_llt, SLOT_RTT);
// 	assert(s2tt != NULL);

// 	s2tte = s2tte_read(&s2tt[wi.index]);
// 	if (!s2tte_is_unassigned(s2_ctx, s2tte)) {
// 		ret = pack_return_code(RMI_ERROR_RTT,
// 					(unsigned char)S2TT_PAGE_LEVEL);
// 		goto out_unmap_ll_table;
// 	}

// 	unsigned int attrs = 10000; //placeholder, no-op
// 	bool used_any = false;
// 	unsigned long pd_addr = rd->pd;

// 	struct parsed_payload cfg;
// 	load_cfg(pd_addr, &cfg);
// 	bool is_fresh = policy_self_ps_is_fresh_for_gpa(&cfg, map_addr);
// 	int psr_id = 0;

// 	if(is_fresh == true){
// 		int rc;
// 		psr_id = get_psr_id_for_ipa_range(&cfg, map_addr);

// 		if(psr_id == -1){
// 			INFO("Error: No PSR found for ipa 0x%lx in config\n", map_addr);
// 			ret = RMI_ERROR_INPUT;
// 			goto out_unmap_ll_table;
// 		}

// 		/* 1) Claim HPA ownership for this PSR (pre-check) */
// 		rc = psr_hpa_claim(psr_id, data_addr);
// 		if (rc != 0) {
// 			INFO("Error: Could not claim HPA ownership for PSR %d\n", psr_id);
// 			ret = RMI_ERROR_INPUT;
// 			goto out_unmap_ll_table;
// 		}
// 	}
	
// 	int target_acl = find_prot_for_mem_with_gpa_in_config(map_addr, rd_addr, pd_addr, &used_any);
// 	if(used_any == true){
// 		INFO("Target acl for ANY=%d\n", target_acl);
// 	}
// 	if(target_acl > 0){
// 		attrs = (unsigned int)target_acl;
// 	} else {
// 		INFO("WARNING: TYPE or TARGET_ACL is 0, mapping to RW\n"); //add failure logic later
// 		attrs = 0; //RW
// 	}
// 	if(attrs != 0){
// 		INFO("Mapping Data Granule at ipa 0x%lx as SHARED with ACL %d in RD 0x%lx\n",
// 			map_addr, target_acl, rd_addr);
// 		// pol_pretty_print();
// 		//replace with s2tte_create_assigned_ram_with_attrs
// 		s2tte = s2tte_create_assigned_ram_with_attrs(s2_ctx, data_addr,
// 							S2TT_PAGE_LEVEL, attrs);

// 		new_data_state = GRANULE_STATE_DATA;

// 		s2tte_write(&s2tt[wi.index], s2tte);
// 		atomic_granule_get(wi.g_llt);

// 		ret = RMI_SUCCESS;

// 		// if(ret == RMI_SUCCESS){
// 		//mark the data granule as shared in some way..other RMI later
// 		// pst_pretty_print();
// 		pst_add_pa(rd_addr, map_addr, data_addr);
// 		// pst_pretty_print();
// 		rd_addr = pst_get_rd_from_pa(data_addr);
// 		// INFO("Data Granule 0x%lx marked as shared in PST for RD 0x%lx\n", data_addr, rd_addr);
// 	} else {
// 		INFO("Error in config, cannot map Data Granule as SHARED\n");
// 		if(is_fresh) {
// 			(void)psr_hpa_release(psr_id, data_addr); //release ownership
// 		}
// 		ret = RMI_ERROR_INPUT;
// 	}

// out_unmap_ll_table:
// 	buffer_unmap(s2tt);
// out_unlock_ll_table:
// 	granule_unlock(wi.g_llt);
// out_unmap_rd:
// 	buffer_unmap(rd);
// 	granule_unlock(g_rd);
// 	granule_unlock_transition(g_data, new_data_state);
// 	if(ret == RMI_SUCCESS){
// 		// INFO("Trying to update mappings for shared data granule at ipa 0x%lx in RD 0x%lx\n",
// 		// 	map_addr, rd_addr);
// 		if(update_mem_sharing_mapped_state(map_addr, rd_addr, pd_addr, used_any) == 0){
// 			// INFO("Could not update mappings\n");
// 		}
// 	}
// 	//rrt_pretty_print();
// 	return ret;
// }

unsigned long smc_data_create(unsigned long rd_addr,
			      unsigned long data_addr,
			      unsigned long map_addr,
			      unsigned long src_addr,
			      unsigned long flags)
{
	struct granule *g_src;

	if ((flags != RMI_NO_MEASURE_CONTENT) &&
	    (flags != RMI_MEASURE_CONTENT)) {
		return RMI_ERROR_INPUT;
	}

	g_src = find_granule(src_addr);
	if ((g_src == NULL) ||
		(granule_unlocked_state(g_src) != GRANULE_STATE_NS)) {
		return RMI_ERROR_INPUT;
	}

	return data_create(rd_addr, data_addr, map_addr, g_src, flags);
}

unsigned long smc_data_create_unknown(unsigned long rd_addr,
				      unsigned long data_addr,
				      unsigned long map_addr)
{
	return data_create(rd_addr, data_addr, map_addr, NULL, 0);
}

// unsigned long smc_data_create_unknown_shared(unsigned long rd_addr,
// 				      unsigned long data_addr,
// 				      unsigned long map_addr)
// {
// 	return data_create_unknown_shared(rd_addr, data_addr, map_addr);
// }

unsigned long smc_realm_bind_protected_shared(unsigned long rd_addr, //this will go
			unsigned long pa,
			unsigned long ipa)
{
	struct s2tt_walk wi;
	struct s2tt_context *s2_ctx;
	unsigned long ret = RMI_SUCCESS;
	struct granule *g_bind_rd;
	struct rd *bind_rd;
	// unsigned long pd_addr;
	
	g_bind_rd = find_lock_granule(rd_addr, GRANULE_STATE_RD);
	if (g_bind_rd == NULL) {
		return RMI_ERROR_INPUT;
	}
	bind_rd = buffer_granule_map(g_bind_rd, SLOT_RD);
	assert(bind_rd != NULL);

	// ret = validate_data_create_unknown_shared(ipa, bind_rd);
	ret = validate_data_create(ipa, bind_rd);
	
	if (ret != RMI_SUCCESS) {
		buffer_unmap(bind_rd);
		granule_unlock(g_bind_rd);
		return RMI_ERROR_INPUT;
	}

	s2_ctx = &(bind_rd->s2_ctx);
	granule_lock(s2_ctx->g_rtt, GRANULE_STATE_RTT);
	s2tt_walk_lock_unlock(s2_ctx, ipa, S2TT_PAGE_LEVEL, &wi);
	if (wi.last_level != S2TT_PAGE_LEVEL) {
		ret = pack_return_code(RMI_ERROR_RTT,
					(unsigned char)wi.last_level);
		granule_unlock(wi.g_llt);
		buffer_unmap(bind_rd);
		granule_unlock(g_bind_rd);
		return ret;
	}
	// pd_addr = bind_rd->pd;
	// struct parsed_payload cfg;
	// load_cfg(pd_addr, &cfg);
	// bool is_fresh = policy_self_ps_is_fresh_for_gpa(&cfg, ipa);
	// int psr_id = 0;
	// if(is_fresh == true){
	// 	int rc;
	// 	psr_id = get_psr_id_for_ipa_range(&cfg, ipa);

	// 	if(psr_id == -1){
	// 		INFO("Error: No PSR found for ipa 0x%lx in config\n", ipa);
	// 		ret = RMI_ERROR_INPUT;
	// 		granule_unlock(wi.g_llt);
	// 		buffer_unmap(bind_rd);
	// 		granule_unlock(g_bind_rd);
	// 		return ret;
	// 	}

	// 	/* 1) Claim HPA ownership for this PSR (pre-check) */
	// 	rc = psr_hpa_claim(psr_id, pa);
	// 	if (rc != 0) {
	// 		INFO("Error: Could not claim HPA ownership for PSR %d\n", psr_id);
	// 		ret = RMI_ERROR_INPUT;
	// 		granule_unlock(wi.g_llt);
	// 		buffer_unmap(bind_rd);
	// 		granule_unlock(g_bind_rd);
	// 		return ret;
	// 	}
	// }
	granule_unlock(wi.g_llt);
	buffer_unmap(bind_rd);
	granule_unlock(g_bind_rd);
	
	// bool used_any = false;
	// ret = map_ipa_to_pa(rd_addr, pa, ipa, &used_any);
	// if(used_any == true){
	// 	INFO("Chosen target acl for ANY\n");
	// }

	// if(ret == RMI_SUCCESS) {
	// 	INFO("Mapped IPA 0x%lx to PA 0x%lx in RD 0x%lx\n",
	// 			ipa, pa, rd_addr);
	// 	// if(update_mem_sharing_mapped_state(ipa, rd_addr, pd_addr, used_any) == 0){
	// 	// 	INFO("Could not update mappings\n");
	// 	// 	// ret = RMI_ERROR_INPUT;
	// 	// }
	// } else{
	// 	// if(is_fresh) {
	// 	// 	(void)psr_hpa_release(psr_id, pa); //release ownership
	// 	// }
		INFO("Error: Could not map IPA 0x%lx to PA 0x%lx in RD 0x%lx\n",
				ipa, pa, rd_addr);
	// }
		
	//rrt_pretty_print();
	return ret;
}

void smc_data_destroy(unsigned long rd_addr,
		      unsigned long map_addr,
		      struct smc_result *res)
{
	struct granule *g_data;
	struct granule *g_rd;
	struct s2tt_walk wi;
	unsigned long data_addr, s2tte, *s2tt;
	struct rd *rd;
	struct s2tt_context s2_ctx;

	g_rd = find_lock_granule(rd_addr, GRANULE_STATE_RD);
	if (g_rd == NULL) {
		res->x[0] = RMI_ERROR_INPUT;
		res->x[2] = 0UL;
		return;
	}

	rd = buffer_granule_map(g_rd, SLOT_RD);
	assert(rd != NULL);

	if (!addr_in_par(rd, map_addr) ||
	    !validate_map_addr(map_addr, S2TT_PAGE_LEVEL, rd)) {
		buffer_unmap(rd);
		granule_unlock(g_rd);
		res->x[0] = RMI_ERROR_INPUT;
		res->x[2] = 0UL;
		return;
	}

	s2_ctx = rd->s2_ctx;
	buffer_unmap(rd);

	granule_lock(s2_ctx.g_rtt, GRANULE_STATE_RTT);
	granule_unlock(g_rd);

	s2tt_walk_lock_unlock(&s2_ctx, map_addr, S2TT_PAGE_LEVEL, &wi);
	s2tt = buffer_granule_map(wi.g_llt, SLOT_RTT);
	assert(s2tt != NULL);

	if (wi.last_level != S2TT_PAGE_LEVEL) {
		res->x[0] = pack_return_code(RMI_ERROR_RTT,
						(unsigned char)wi.last_level);
		goto out_unmap_ll_table;
	}

	s2tte = s2tte_read(&s2tt[wi.index]);

	if (s2tte_is_assigned_ram(&s2_ctx, s2tte, S2TT_PAGE_LEVEL)) {
		data_addr = s2tte_pa(&s2_ctx, s2tte, S2TT_PAGE_LEVEL);
		s2tte = s2tte_create_unassigned_destroyed(&s2_ctx);
		s2tte_write(&s2tt[wi.index], s2tte);
		s2tt_invalidate_page(&s2_ctx, map_addr);
	} else if (s2tte_is_assigned_empty(&s2_ctx, s2tte, S2TT_PAGE_LEVEL)) {
		data_addr = s2tte_pa(&s2_ctx, s2tte, S2TT_PAGE_LEVEL);
		s2tte = s2tte_create_unassigned_empty(&s2_ctx);
		s2tte_write(&s2tt[wi.index], s2tte);
	} else if (s2tte_is_assigned_destroyed(&s2_ctx, s2tte,
					       S2TT_PAGE_LEVEL)) {
		data_addr = s2tte_pa(&s2_ctx, s2tte, S2TT_PAGE_LEVEL);
		s2tte = s2tte_create_unassigned_destroyed(&s2_ctx);
		s2tte_write(&s2tt[wi.index], s2tte);
	} else {
		res->x[0] = pack_return_code(RMI_ERROR_RTT,
						(unsigned char)S2TT_PAGE_LEVEL);
		goto out_unmap_ll_table;
	}

	atomic_granule_put(wi.g_llt);

	/*
	 * Lock the data granule and check expected state. Correct locking order
	 * is guaranteed because granule address is obtained from a locked
	 * granule by table walk. This lock needs to be acquired before a state
	 * transition to or from GRANULE_STATE_DATA for granule address can happen.
	 */
	g_data = find_lock_granule(data_addr, GRANULE_STATE_DATA);
	assert(g_data != NULL);
	buffer_granule_memzero(g_data, SLOT_DELEGATED);
	granule_unlock_transition(g_data, GRANULE_STATE_DELEGATED);

	res->x[0] = RMI_SUCCESS;
	res->x[1] = data_addr;
out_unmap_ll_table:
	res->x[2] = s2tt_skip_non_live_entries(&s2_ctx, map_addr, s2tt, &wi);
	buffer_unmap(s2tt);
	granule_unlock(wi.g_llt);
}

/*
 * Update the ripas value for the entry pointed by @s2ttep.
 *
 * Returns:
 *  < 0  - On error and the operation was aborted,
 *	   e.g., entry cannot have a ripas.
 *    0  - Operation was success and no TLBI is required.
 *  > 0  - Operation was success and TLBI is required.
 * Sets:
 * @(*do_tlbi) to 'true' if the TLBs have to be invalidated.
 */
static int update_ripas(const struct s2tt_context *s2_ctx,
			unsigned long *s2ttep, long level,
			enum ripas ripas_val,
			enum ripas_change_destroyed change_destroyed)
{
	unsigned long pa, s2tte = s2tte_read(s2ttep);
	int ret = 0;

	assert(s2_ctx != NULL);

	if (!s2tte_has_ripas(s2_ctx, s2tte, level)) {
		return -EPERM;
	}

	if (ripas_val == RIPAS_RAM) {
		if (s2tte_is_unassigned_empty(s2_ctx, s2tte)) {
			s2tte = s2tte_create_unassigned_ram(s2_ctx);
		} else if (s2tte_is_unassigned_destroyed(s2_ctx, s2tte)) {
			if (change_destroyed == CHANGE_DESTROYED) {
				s2tte = s2tte_create_unassigned_ram(s2_ctx);
			} else {
				return -EINVAL;
			}
		} else if (s2tte_is_assigned_empty(s2_ctx, s2tte, level)) {
			pa = s2tte_pa(s2_ctx, s2tte, level);
			s2tte = s2tte_create_assigned_ram(s2_ctx, pa, level);
		} else if (s2tte_is_assigned_destroyed(s2_ctx, s2tte, level)) {
			if (change_destroyed == CHANGE_DESTROYED) {
				pa = s2tte_pa(s2_ctx, s2tte, level);
				s2tte = s2tte_create_assigned_ram(s2_ctx, pa,
								  level);
			} else {
				return -EINVAL;
			}
		} else {
			/* No action is required */
			return 0;
		}
	} else if (ripas_val == RIPAS_EMPTY) {
		if (s2tte_is_unassigned_ram(s2_ctx, s2tte)) {
			s2tte = s2tte_create_unassigned_empty(s2_ctx);
		} else if (s2tte_is_unassigned_destroyed(s2_ctx, s2tte)) {
			if (change_destroyed == CHANGE_DESTROYED) {
				s2tte = s2tte_create_unassigned_empty(s2_ctx);
			} else {
				return -EINVAL;
			}
		} else if (s2tte_is_assigned_ram(s2_ctx, s2tte, level)) {
			pa = s2tte_pa(s2_ctx, s2tte, level);
			s2tte = s2tte_create_assigned_empty(s2_ctx, pa, level);
			/* TLBI is required */
			ret = 1;
		} else if (s2tte_is_assigned_destroyed(s2_ctx, s2tte, level)) {
			if (change_destroyed == CHANGE_DESTROYED) {
				pa = s2tte_pa(s2_ctx, s2tte, level);
				s2tte = s2tte_create_assigned_empty(s2_ctx,
								    pa, level);
				/* TLBI is required */
				ret = 1;
			} else {
				return -EINVAL;
			}
		} else {
			/* No action is required */
			return 0;
		}
	}
	s2tte_write(s2ttep, s2tte);
	return ret;
}

void smc_rtt_init_ripas(unsigned long rd_addr,
			unsigned long base,
			unsigned long top,
			struct smc_result *res)
{
	struct granule *g_rd;
	struct rd *rd;
	unsigned long addr, map_size;
	struct s2tt_walk wi;
	struct s2tt_context *s2_ctx;
	unsigned long s2tte, *s2tt;
	long level;
	unsigned long index;
	unsigned int s2ttes_per_s2tt;

	if (top <= base) {
		res->x[0] = RMI_ERROR_INPUT;
		return;
	}

	g_rd = find_lock_granule(rd_addr, GRANULE_STATE_RD);
	if (g_rd == NULL) {
		res->x[0] = RMI_ERROR_INPUT;
		return;
	}

	rd = buffer_granule_map(g_rd, SLOT_RD);
	assert(rd != NULL);

	if (!validate_map_addr(base, S2TT_PAGE_LEVEL, rd) ||
	    !validate_map_addr(top, S2TT_PAGE_LEVEL, rd) ||
	    !addr_in_par(rd, base) || !addr_in_par(rd, top - GRANULE_SIZE)) {
		buffer_unmap(rd);
		granule_unlock(g_rd);
		res->x[0] = RMI_ERROR_INPUT;
		return;
	}

	if (get_rd_state_locked(rd) != REALM_NEW) {
		buffer_unmap(rd);
		granule_unlock(g_rd);
		res->x[0] = RMI_ERROR_REALM;
		return;
	}

	s2_ctx = &(rd->s2_ctx);
	granule_lock(s2_ctx->g_rtt, GRANULE_STATE_RTT);

	s2tt_walk_lock_unlock(s2_ctx, base, S2TT_PAGE_LEVEL, &wi);
	level = wi.last_level;
	s2tt = buffer_granule_map(wi.g_llt, SLOT_RTT);
	assert(s2tt != NULL);

	map_size = s2tte_map_size(level);
	addr = base & ~(map_size - 1UL);

	/*
	 * If the RTTE covers a range below "base", we need to go deeper.
	 */
	if (addr != base) {
		res->x[0] = pack_return_code(RMI_ERROR_RTT,
						(unsigned char)level);
		goto out_unmap_llt;
	}

	s2ttes_per_s2tt =
		(unsigned int)((level == S2TT_MIN_STARTING_LEVEL_LPA2) ?
			S2TTES_PER_S2TT_LM1 : S2TTES_PER_S2TT);
	for (index = wi.index; index < s2ttes_per_s2tt; index++) {
		unsigned long next = addr + map_size;

		/*
		 * Break on "top_align" failure condition,
		 * or if this entry crosses the range.
		 */
		if (next > top) {
			break;
		}

		s2tte = s2tte_read(&s2tt[index]);
		if (s2tte_is_unassigned_empty(s2_ctx, s2tte)) {
			s2tte = s2tte_create_unassigned_ram(s2_ctx);
			s2tte_write(&s2tt[index], s2tte);
		} else if (!s2tte_is_unassigned_ram(s2_ctx, s2tte)) {
			break;
		}
		measurement_init_ripas_measure(rd->measurement[RIM_MEASUREMENT_SLOT],
					       rd->algorithm,
					       addr,
					       next);
		addr = next;
	}

	if (addr > base) {
		res->x[0] = RMI_SUCCESS;
		res->x[1] = addr;
	} else {
		res->x[0] = pack_return_code(RMI_ERROR_RTT,
						(unsigned char)level);
	}

out_unmap_llt:
	buffer_unmap(s2tt);
	buffer_unmap(rd);
	granule_unlock(wi.g_llt);
	granule_unlock(g_rd);
}

static void rtt_set_ripas_range(struct s2tt_context *s2_ctx,
				unsigned long *s2tt,
				unsigned long base,
				unsigned long top,
				struct s2tt_walk *wi,
				enum ripas ripas_val,
				enum ripas_change_destroyed change_destroyed,
				struct smc_result *res)
{
	unsigned long index;
	long level = wi->last_level;
	unsigned long map_size = s2tte_map_size((int)level);

	/* Align to the RTT level */
	unsigned long addr = base & ~(map_size - 1UL);

	/* Make sure we don't touch a range below the requested range */
	if (addr != base) {
		res->x[0] = pack_return_code(RMI_ERROR_RTT,
						(unsigned char)level);
		return;
	}

	for (index = wi->index; index < S2TTES_PER_S2TT; index++) {
		int ret;

		/*
		 * Break on "top_align" failure condition,
		 * or if this entry crosses the range.
		 */
		if ((addr + map_size) > top) {
			break;
		}

		ret = update_ripas(s2_ctx, &s2tt[index], level,
					ripas_val, change_destroyed);
		if (ret < 0) {
			break;
		}

		/* Handle TLBI */
		if (ret != 0) {
			if (level == S2TT_PAGE_LEVEL) {
				s2tt_invalidate_page(s2_ctx, addr);
			} else {
				s2tt_invalidate_block(s2_ctx, addr);
			}
		}

		addr += map_size;
	}

	if (addr > base) {
		res->x[0] = RMI_SUCCESS;
		res->x[1] = addr;
	} else {
		res->x[0] = pack_return_code(RMI_ERROR_RTT,
						(unsigned char)level);
	}
}

void smc_rtt_set_ripas(unsigned long rd_addr,
		       unsigned long rec_addr,
		       unsigned long base,
		       unsigned long top,
		       struct smc_result *res)
{
	struct granule *g_rd, *g_rec;
	struct rec *rec;
	struct rd *rd;
	struct s2tt_walk wi;
	unsigned long *s2tt;
	struct s2tt_context *s2_ctx;
	enum ripas ripas_val;
	enum ripas_change_destroyed change_destroyed;

	if ((top <= base) || !GRANULE_ALIGNED(top)) {
		res->x[0] = RMI_ERROR_INPUT;
		return;
	}

	if (!find_lock_two_granules(rd_addr,
				   GRANULE_STATE_RD,
				   &g_rd,
				   rec_addr,
				   GRANULE_STATE_REC,
				   &g_rec)) {
		res->x[0] = RMI_ERROR_INPUT;
		return;
	}

	if (granule_refcount_read_acquire(g_rec) != 0U) {
		res->x[0] = RMI_ERROR_REC;
		goto out_unlock_rec_rd;
	}

	rec = buffer_granule_map(g_rec, SLOT_REC);
	assert(rec != NULL);

	if (g_rd != rec->realm_info.g_rd) {
		res->x[0] = RMI_ERROR_REC;
		goto out_unmap_rec;
	}

	ripas_val = rec->set_ripas.ripas_val;
	change_destroyed = rec->set_ripas.change_destroyed;

	/*
	 * Return error in case of target region:
	 * - is not the next chunk of requested region
	 * - extends beyond the end of requested region
	 */
	if ((base != rec->set_ripas.addr) || (top > rec->set_ripas.top)) {
		res->x[0] = RMI_ERROR_INPUT;
		goto out_unmap_rec;
	}

	rd = buffer_granule_map(g_rd, SLOT_RD);
	assert(rd != NULL);

	/*
	 * At this point, we know base == rec->set_ripas.addr
	 * and thus must be aligned to GRANULE size.
	 */
	assert(validate_map_addr(base, S2TT_PAGE_LEVEL, rd));

	s2_ctx = &(rd->s2_ctx);
	granule_lock(s2_ctx->g_rtt, GRANULE_STATE_RTT);

	/* Walk to the deepest level possible */
	s2tt_walk_lock_unlock(s2_ctx, base, S2TT_PAGE_LEVEL, &wi);

	/*
	 * Base has to be aligned to the level at which
	 * it is mapped in RTT.
	 */
	if (!validate_map_addr(base, wi.last_level, rd)) {
		res->x[0] = pack_return_code(RMI_ERROR_RTT,
						(unsigned char)wi.last_level);
		goto out_unlock_llt;
	}

	s2tt = buffer_granule_map(wi.g_llt, SLOT_RTT);
	assert(s2tt != NULL);

	rtt_set_ripas_range(s2_ctx, s2tt, base, top, &wi,
				ripas_val, change_destroyed, res);

	if (res->x[0] == RMI_SUCCESS) {
		rec->set_ripas.addr = res->x[1];
	}

	buffer_unmap(s2tt);
out_unlock_llt:
	granule_unlock(wi.g_llt);
	buffer_unmap(rd);
out_unmap_rec:
	buffer_unmap(rec);
out_unlock_rec_rd:
	granule_unlock(g_rec);
	granule_unlock(g_rd);
}

unsigned long smc_dev_mem_map(unsigned long rd_addr,
				unsigned long map_addr,
				unsigned long ulevel,
				unsigned long dev_mem_addr)
{
	(void)rd_addr;
	(void)map_addr;
	(void)ulevel;
	(void)dev_mem_addr;
	return RMI_ERROR_NOT_SUPPORTED;
}

void smc_dev_mem_unmap(unsigned long rd_addr,
			unsigned long map_addr,
			unsigned long ulevel,
			struct smc_result *res)
{
	(void)rd_addr;
	(void)map_addr;
	(void)ulevel;
	res->x[0] = RMI_ERROR_NOT_SUPPORTED;
	res->x[1] = 0UL;
	res->x[2] = 0UL;
}
