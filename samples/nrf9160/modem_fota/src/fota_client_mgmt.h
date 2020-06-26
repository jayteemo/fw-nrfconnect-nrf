/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */
#include <string.h>

int fota_client_generate_jwt(const char * const device_id, char ** jwt_out);
int fota_client_provision_device(void);
int fota_client_get_pending_job(void);
