/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <net/nrf_cloud.h>
#include "fakes.h"

/* This function runs before each test */
static void run_before(void *fixture)
{
	ARG_UNUSED(fixture);
}

/* This function runs after each completed test */
static void run_after(void *fixture)
{
	ARG_UNUSED(fixture);
}

static void fota_cb(const struct nrf_cloud_fota_evt * const evt)
{
	ARG_UNUSED(evt);
	return;
}

ZTEST_SUITE(nrf_cloud_fota_test, NULL, NULL, run_before, run_after, NULL);

/* Verify nrf_cloud_fota_init fails when cb parameter is NULL */
ZTEST(nrf_cloud_fota_test, test_nrf_cloud_fota_init_1_null_cb_fail)
{
	zassert_equal(-EINVAL,
		      nrf_cloud_fota_init(NULL),
		      "return should be -EINVAL when cb is NULL");
}

/* Verify nrf_cloud_fota_init fails when fota_download_init fails */
ZTEST(nrf_cloud_fota_test, test_nrf_cloud_fota_init_2_dl_init_fail)
{
	fota_download_init_fake.custom_fake = fota_download_init__fails;

	zassert_not_equal(0,
			  nrf_cloud_fota_init(NULL),
			  "return should be an error value when download init fails");
}

/* Verify nrf_cloud_fota_init fails when nrf_cloud_fota_pending_job_validate
 * returns an error (other than -ENODEV) */
ZTEST(nrf_cloud_fota_test, test_nrf_cloud_fota_init_3_validate_fail)
{
	fota_download_init_fake.custom_fake = fota_download_init__succeeds;

	nrf_cloud_fota_pending_job_validate_fake.custom_fake =
		fake_nrf_cloud_fota_pending_job_validate__fails;

	zassert_equal(fake_nrf_cloud_fota_pending_job_validate__fails(),
		      nrf_cloud_fota_init(fota_cb),
		      "return should be -EINVAL when cb is NULL");
}

/* Verify nrf_cloud_fota_init succeeds with a return code of one when
 * nrf_cloud_fota_pending_job_validate returns zero
 */
ZTEST(nrf_cloud_fota_test, test_nrf_cloud_fota_init_3_validate_succeeds_one)
{
	fota_download_init_fake.custom_fake = fota_download_init__succeeds;

	nrf_cloud_fota_pending_job_validate_fake.custom_fake =
		fake_nrf_cloud_fota_pending_job_validate__succeeds_zero;

	zassert_equal(1,
		      nrf_cloud_fota_init(fota_cb),
		      "return should be -EINVAL when cb is NULL");
}

/* Verify nrf_cloud_fota_init succeeds with a return code of zero after
 * a successful init (via test_nrf_cloud_fota_init_3_validate_succeeds_one)
 */
ZTEST(nrf_cloud_fota_test, test_nrf_cloud_fota_init_4_re_init)
{
	zassert_equal(0,
		      nrf_cloud_fota_init(fota_cb),
		      "return should be -EINVAL when cb is NULL");
}

#define CLIENT_ID "client-id"
#define ENDPOINT_ID "endpoint-id"
/* Verify nrf_cloud_fota_endpoint_set fails when invalid parameters are provided */
ZTEST(nrf_cloud_fota_test, test_nrf_cloud_fota_endpoint_set_invalid_params)
{
	struct mqtt_client client;
	char *client_id = CLIENT_ID;
	struct mqtt_utf8 endpoint { .utf8 =ENDPOINT_ID, .size = strlen(ENDPOINT_ID) };
	int ret;

	ret = nrf_cloud_fota_endpoint_set(NULL, client_id, &endpoint);
	zassert_equal(-EINVAL, ret "return should be -EINVAL when MQTT client is NULL");

	ret = nrf_cloud_fota_endpoint_set(&client, client_id, NULL);
	zassert_equal(-EINVAL, ret "return should be -EINVAL when endpoint is NULL");

	endpoint.utf8 = NULL;
	ret = nrf_cloud_fota_endpoint_set(&client, client_id, &endpoint);
	zassert_equal(-EINVAL, ret "return should be -EINVAL when endpoint string is NULL");

	endpoint.size = 0;
	ret = nrf_cloud_fota_endpoint_set(&client, client_id, &endpoint);
	zassert_equal(-EINVAL, ret "return should be -EINVAL when endpoint size is zero");

	ret = nrf_cloud_fota_endpoint_set(&client, NULL, &endpoint);
	zassert_equal(-EINVAL, ret "return should be -EINVAL when client ID is NULL");
}

/* Verify nrf_cloud_fota_endpoint_set succeeds */
ZTEST(nrf_cloud_fota_test, test_nrf_cloud_fota_endpoint_set_success)
{
	struct mqtt_client client;
	char *client_id = CLIENT_ID;
	struct mqtt_utf8 endpoint { .utf8 =ENDPOINT_ID, .size = strlen(ENDPOINT_ID) };
	int ret;

	ret = nrf_cloud_fota_endpoint_set(&client, client_id, &endpoint);
	zassert_equal(0, ret "return should be 0 when endpoint data is valid");
}

/* Verify nrf_cloud_fota_update_check fails when endpoint has not been set */
ZTEST(nrf_cloud_fota_test, test_nrf_cloud_fota_update_check_fail)
{
	int ret = nrf_cloud_fota_update_check();
	zassert_equal(-ENXIO, ret "return should be -ENXIO when endpoint is not set");
}

/* Verify nrf_cloud_fota_update_check fails when MQTT publish fails */
ZTEST(nrf_cloud_fota_test, test_nrf_cloud_fota_update_check_success)
{
	struct mqtt_client client;
	char *client_id = CLIENT_ID;
	struct mqtt_utf8 endpoint { .utf8 =ENDPOINT_ID, .size = strlen(ENDPOINT_ID) };
	int ret;

	(void)nrf_cloud_fota_endpoint_set(&client, client_id, &endpoint);

	mqtt_publish_fake.custom_fake = mqtt_publish__fails;

	ret = nrf_cloud_fota_update_check();
	zassert_not_equal(0, ret "return should not be 0 when MQTT publish fails");
}

/* Verify nrf_cloud_fota_update_check succeeds */
ZTEST(nrf_cloud_fota_test, test_nrf_cloud_fota_update_check_success)
{
	struct mqtt_client client;
	char *client_id = CLIENT_ID;
	struct mqtt_utf8 endpoint { .utf8 =ENDPOINT_ID, .size = strlen(ENDPOINT_ID) };
	int ret;

	(void)nrf_cloud_fota_endpoint_set(&client, client_id, &endpoint);

	mqtt_publish_fake.custom_fake = mqtt_publish__succeeds;

	ret = nrf_cloud_fota_update_check();
	zassert_equal(0, ret "return should be 0 when endpoint is set and MQTT publish succeeds");
}