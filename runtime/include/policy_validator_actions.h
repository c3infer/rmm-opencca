/* policy_validator_actions.h */
#ifndef POLICY_VALIDATOR_ACTIONS_H
#define POLICY_VALIDATOR_ACTIONS_H

#include <stddef.h>
#include <stdint.h>

#include <policy_parser.h>
#include <sgt.h>

#include <policy_validator.h>
#include <realm.h>

#include <buffer.h>
#include <debug.h>
#include <granule.h>
#include <s2tt.h>

void policy_validator_actions_set_s2_ctx(const struct s2tt_context *s2_ctx,
                                         unsigned long start_ipa);
void policy_validator_actions_clear_s2_ctx(void);

int apply_mem_actions(struct parsed_payload *self_cfg,
                      const struct sgt *sgt,
                      const char mem_name[4]);

#endif /* POLICY_VALIDATOR_ACTIONS_H */
