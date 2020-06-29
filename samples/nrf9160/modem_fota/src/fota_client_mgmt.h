/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

struct fota_client_mgmt_job {

	/** Hostname for download */
	char * host;
	/** Path for download */
	char * path;

	/* TODO */
	/** Job ID */
	char * id;
	/** Job status */
	int status;
	/** Job status details */
	char * status_details;
};

int fota_client_provision_device(void);
int fota_client_get_pending_job(struct fota_client_mgmt_job * const job);
int fota_client_update_job(const struct fota_client_mgmt_job * job);
