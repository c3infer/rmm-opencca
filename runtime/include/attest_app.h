/*
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ATTEST_APP_H
#define ATTEST_APP_H

#include <app.h>
#include <attest_defs.h>
#include <attestation_token.h>
#include <measurement.h>
#include <stddef.h>
#include <stdint.h>

void attest_do_hash(unsigned int algorithm,
		    void *data,
		    size_t size,
		    unsigned char *out);

void attest_do_extend(struct app_data_cfg *app_data,
		      enum hash_algo algorithm,
		      void *current_measurement,
		      void *extend_measurement,
		      size_t extend_measurement_size,
		      unsigned char *out,
		      size_t out_size);

int attest_app_global_init(void);
void attest_app_init_per_cpu_instance(void);
int attest_app_init(struct app_data_cfg *app_data,
	    uintptr_t granule_pas[],
	    size_t granule_pa_count,
	    void *granule_va_start);

enum attest_token_err_t compat_attest_realm_token_sign(struct app_data_cfg *app_data,
					       size_t *realm_token_len);
enum attest_token_err_t compat_attest_cca_token_create(struct app_data_cfg *app_data,
					       size_t *attest_token_len);
enum attest_token_err_t compat_attest_token_sign_ctx_init(struct app_data_cfg *app_data,
						   uintptr_t cookie);
enum attest_token_err_t compat_attest_realm_token_create(struct app_data_cfg *app_data,
					 enum hash_algo algorithm,
					 unsigned char measurements[][MAX_MEASUREMENT_SIZE],
					 const void *rpv_buf,
					 const void *challenge_buf);

int compat_attest_el3_token_write_response_to_ctx(struct app_data_cfg *app_data,
						  uintptr_t cookie);

int attest_app_el3_token_write_response_to_ctx(struct app_data_cfg *app_data,
					       uint64_t req_ticket,
					       size_t signature_buf_len,
					       uint8_t signature_buf[]);

#define attest_realm_token_sign compat_attest_realm_token_sign
#define attest_cca_token_create compat_attest_cca_token_create
#define attest_token_sign_ctx_init compat_attest_token_sign_ctx_init
#define attest_realm_token_create compat_attest_realm_token_create
#define attest_el3_token_write_response_to_ctx compat_attest_el3_token_write_response_to_ctx

#endif /* ATTEST_APP_H */
