/*
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <app.h>
#include <app_header.h>
#include <attest_app.h>
#include <attestation.h>
#include <errno.h>
#include <measurement.h>
#include <random_app.h>
#include <smc-rmi.h>
#include <string.h>

#undef attest_realm_token_sign
#undef attest_cca_token_create
#undef attest_token_sign_ctx_init
#undef attest_realm_token_create
#undef attest_el3_token_write_response_to_ctx

static struct attest_heap_shared fallback_heap[MAX_CPUS];
static unsigned char fallback_realm_token_buf[MAX_CPUS][RMM_REALM_TOKEN_BUF_SIZE];

static unsigned int app_slot(const struct app_data_cfg *app_data)
{
	return (unsigned int)(((uintptr_t)app_data >> 6U) % MAX_CPUS);
}

void app_framework_setup(void) {}
void app_info_setup(void) {}

int app_init_data(struct app_data_cfg *app_data,
		  unsigned long app_id,
		  uintptr_t granule_pas[],
		  size_t granule_count,
		  void *granule_va_start)
{
	(void)app_id;
	(void)granule_pas;
	(void)granule_count;
	(void)granule_va_start;

	if (app_data == NULL) {
		return -EINVAL;
	}

	(void)memset(app_data, 0, sizeof(*app_data));
	app_data->heap_shared = &fallback_heap[app_slot(app_data)];
	app_data->realm_token_buf = fallback_realm_token_buf[app_slot(app_data)];
	app_data->realm_token_buf_size = sizeof(fallback_realm_token_buf[0]);
	app_data->initialized = true;
	return 0;
}

void *app_get_heap_ptr(struct app_data_cfg *app_data)
{
	if ((app_data == NULL) || (app_data->heap_shared == NULL)) {
		return NULL;
	}
	return app_data->heap_shared;
}

unsigned long app_run(struct app_data_cfg *app_data,
		      unsigned long app_func_id,
		      unsigned long arg0,
		      unsigned long arg1,
		      unsigned long arg2,
		      unsigned long arg3)
{
	(void)app_data;
	(void)app_func_id;
	(void)arg0;
	(void)arg1;
	(void)arg2;
	(void)arg3;
	return 0UL;
}

void app_map_shared_page(struct app_data_cfg *app_data) { (void)app_data; }
void app_unmap_shared_page(struct app_data_cfg *app_data) { (void)app_data; }

void random_app_init_prng(void) {}
struct app_data_cfg *random_app_get_data_cfg(void) { return NULL; }

int random_app_prng_get_random(struct app_data_cfg *app_data, uint8_t *buf, size_t output_size)
{
	(void)app_data;
	if ((buf == NULL) || (output_size == 0UL)) {
		return -EINVAL;
	}
	(void)memset(buf, 0, output_size);
	return 0;
}

void attest_do_hash(unsigned int algorithm, void *data, size_t size, unsigned char *out)
{
	measurement_hash_compute((enum hash_algo)algorithm, data, size, out);
}

void attest_do_extend(struct app_data_cfg *app_data,
		      enum hash_algo algorithm,
		      void *current_measurement,
		      void *extend_measurement,
		      size_t extend_measurement_size,
		      unsigned char *out,
		      size_t out_size)
{
	(void)app_data;
	measurement_extend(algorithm, current_measurement, extend_measurement,
			   extend_measurement_size, out, out_size);
}

int attest_app_global_init(void)
{
	return attestation_init();
}

void attest_app_init_per_cpu_instance(void) {}

int attest_app_init(struct app_data_cfg *app_data,
	    uintptr_t granule_pas[],
	    size_t granule_pa_count,
	    void *granule_va_start)
{
	return app_init_data(app_data, 0UL, granule_pas, granule_pa_count, granule_va_start);
}

enum attest_token_err_t compat_attest_token_sign_ctx_init(struct app_data_cfg *app_data,
						   uintptr_t cookie)
{
	if ((app_data == NULL) || (app_data->heap_shared == NULL)) {
		return ATTEST_TOKEN_ERR_INVALID_STATE;
	}

	if (attest_token_ctx_init(&app_data->token_ctx,
				 (unsigned char *)app_data->heap_shared,
				 ATTEST_TOKEN_BUF_SIZE,
				 cookie) != 0) {
		return ATTEST_TOKEN_ERR_INVALID_STATE;
	}

	return ATTEST_TOKEN_ERR_SUCCESS;
}

enum attest_token_err_t compat_attest_realm_token_create(struct app_data_cfg *app_data,
						 enum hash_algo algorithm,
						 unsigned char measurements[][MAX_MEASUREMENT_SIZE],
						 const void *rpv_buf,
						 const void *challenge_buf)
{
	int ret;

	if ((app_data == NULL) || (app_data->realm_token_buf == NULL)) {
		return ATTEST_TOKEN_ERR_INVALID_STATE;
	}

	ret = attest_realm_token_create(algorithm,
				measurements,
				MEASUREMENT_SLOT_NR,
				rpv_buf,
				RPV_SIZE,
				challenge_buf,
				ATTEST_CHALLENGE_SIZE,
				&app_data->token_ctx,
				app_data->realm_token_buf,
				app_data->realm_token_buf_size);
	if (ret != 0) {
		return ATTEST_TOKEN_ERR_INVALID_STATE;
	}

	app_data->realm_token_len = 0UL;
	return ATTEST_TOKEN_ERR_SUCCESS;
}

enum attest_token_err_t compat_attest_realm_token_sign(struct app_data_cfg *app_data,
					       size_t *realm_token_len)
{
	enum attest_token_err_t ret;

	if ((app_data == NULL) || (realm_token_len == NULL)) {
		return ATTEST_TOKEN_ERR_INVALID_STATE;
	}

	ret = attest_realm_token_sign(&app_data->token_ctx, realm_token_len);
	if ((ret == ATTEST_TOKEN_ERR_SUCCESS) ||
	    (ret == ATTEST_TOKEN_ERR_COSE_SIGN_IN_PROGRESS)) {
		app_data->realm_token_len = *realm_token_len;
	}

	return ret;
}

enum attest_token_err_t compat_attest_cca_token_create(struct app_data_cfg *app_data,
					       size_t *attest_token_len)
{
	if ((app_data == NULL) || (attest_token_len == NULL) ||
	    (app_data->heap_shared == NULL) || (app_data->realm_token_buf == NULL) ||
	    (app_data->realm_token_len == 0UL)) {
		return ATTEST_TOKEN_ERR_INVALID_STATE;
	}

	return attest_cca_token_create(&app_data->token_ctx,
				       app_data->heap_shared->cca_attest_token_buf,
				       ATTEST_TOKEN_BUF_SIZE,
				       app_data->realm_token_buf,
				       app_data->realm_token_len,
				       attest_token_len);
}

int attest_app_el3_token_write_response_to_ctx(struct app_data_cfg *app_data,
					       uint64_t req_ticket,
					       size_t signature_buf_len,
					       uint8_t signature_buf[])
{
	(void)app_data;
	(void)req_ticket;
	(void)signature_buf_len;
	(void)signature_buf;
	return -ENOTSUP;
}

int compat_attest_el3_token_write_response_to_ctx(struct app_data_cfg *app_data, uintptr_t cookie)
{
	if (app_data == NULL) {
		return -EINVAL;
	}

	return attest_el3_token_write_response_to_ctx(&app_data->token_ctx, cookie);
}
