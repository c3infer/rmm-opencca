/* policy_validator.h */
#ifndef POLICY_VALIDATOR_H
#define POLICY_VALIDATOR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <policy_parser.h>
#include <sgt.h>
#include <string.h>
#include <debug.h>
#include <granule.h> /* GRANULE_SIZE */
#include <realm_add_meta.h>
#include <transition_table.h>
#include <policy_validator_actions.h>

/*
 * Validation return codes (negative = failure).
 * Keep this small; callers typically only need success/fail + INFO logs.
 */
enum pval_rc {
	PVAL_OK               = 0,

	PVAL_EARGS            = -1,  /* bad args */
	PVAL_ENOMEM_NOTFOUND  = -2,  /* mem_name not found or not PROTECTED */
	PVAL_EPEERLIST_EMPTY  = -3,  /* no peers could be loaded (after load_cfg filtering) */
	PVAL_ECFG_MISMATCH    = -4,  /* peer cfg does not match (type/size/maps/prot/vm props) */
	PVAL_ESGT_CONFLICT    = -5,  /* GPA->PA conflict for same page */
	PVAL_ESGT_COVERAGE    = -6,  /* region not fully covered in SGT */
	PVAL_ESGT_RD_ILLEGAL  = -7,  /* illegal RD present (no ANY or exceeds ANY count) */
	PVAL_EWRITEBACK       = -8,  /* upload_cfg failed for some cfg */
	PVAL_ESGT			  = -9,
};

/* ---- Required environment stubs (platform-specific) ---- */

/*
 * Translate a VM hash to a peer RD (Realm descriptor).
 * Return true on success. You will wire this into your real mapping.
 */
bool get_peer_rd(uint32_t peer_hash, unsigned long *out_rd);

/*
 * Translate a peer RD to that peer's policy-granule address (PD address).
 * Return true on success.
 */
bool get_peer_pd_addr(unsigned long rd, unsigned long *out_pd_addr);

/*
 * Validate one PROTECTED memory region named mem_name in self_cfg against:
 *  - peer policies loaded via (hash -> rd -> pd_addr -> load_cfg),
 *  - and the SGT tuples (PA,GPA,RD).
 *
 * On success:
 *  - validates policy consistency against SGT and peers,
 *  - and applies mapping actions in the current Realm only.
 */
int validate_and_activate_mem(struct parsed_payload *self_cfg,
                              unsigned long self_pd_addr,
                              const struct sgt *sgt,
                              const char mem_name[4]);

/*
 * Wrapper: iterate all self_cfg memories, and for each MEM_PROTECTED region call
 * validate_and_activate_mem(). Stops on first failure.
 */
int validate_and_activate_all_protected(struct parsed_payload *self_cfg,
                                        unsigned long self_pd_addr);

#endif /* POLICY_VALIDATOR_H */
