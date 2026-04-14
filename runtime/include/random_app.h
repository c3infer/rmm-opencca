/*
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef RANDOM_APP_H
#define RANDOM_APP_H

#include <app.h>
#include <stddef.h>
#include <stdint.h>

void random_app_init_prng(void);
struct app_data_cfg *random_app_get_data_cfg(void);
int random_app_prng_get_random(struct app_data_cfg *app_data, uint8_t *buf, size_t output_size);

#endif /* RANDOM_APP_H */
