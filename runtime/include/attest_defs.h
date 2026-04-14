/*
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ATTEST_DEFS_H
#define ATTEST_DEFS_H

#include <measurement.h>
#include <sizes.h>
#include <utils_def.h>

#define ATTEST_TOKEN_BUF_SIZE	(RMM_CCA_TOKEN_BUFFER * SZ_4K)
#define RMM_REALM_TOKEN_BUF_SIZE	SZ_1K
#define PD_MEASUREMENT_SLOT		(1U)

struct attest_heap_shared {
	uint8_t cca_attest_token_buf[ATTEST_TOKEN_BUF_SIZE];
};

#endif /* ATTEST_DEFS_H */
