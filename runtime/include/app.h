/*
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef APP_H
#define APP_H

#include <attestation_token.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct attest_heap_shared;

struct app_data_cfg {
	struct token_sign_cntxt token_ctx;
	struct attest_heap_shared *heap_shared;
	unsigned char *realm_token_buf;
	size_t realm_token_buf_size;
	size_t realm_token_len;
	bool initialized;
};

void app_framework_setup(void);
int app_init_data(struct app_data_cfg *app_data,
		  unsigned long app_id,
		  uintptr_t granule_pas[],
		  size_t granule_count,
		  void *granule_va_start);
void *app_get_heap_ptr(struct app_data_cfg *app_data);
unsigned long app_run(struct app_data_cfg *app_data,
		      unsigned long app_func_id,
		      unsigned long arg0,
		      unsigned long arg1,
		      unsigned long arg2,
		      unsigned long arg3);
void app_map_shared_page(struct app_data_cfg *app_data);
void app_unmap_shared_page(struct app_data_cfg *app_data);

#endif /* APP_H */
