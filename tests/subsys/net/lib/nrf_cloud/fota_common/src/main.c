/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <net/nrf_cloud.h>
#include "fakes.h"

/* This function runs before each test */
static void run_before(void *fixture)
{
	ARG_UNUSED(fixture);

	RESET_FAKE(fota_download_s0_active_get);
	RESET_FAKE(boot_is_img_confirmed);
	RESET_FAKE(boot_write_img_confirmed);
	RESET_FAKE(dfu_target_full_modem_cfg);
	RESET_FAKE(dfu_target_full_modem_fdev_get);

#if defined(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE)
	RESET_FAKE(nrf_modem_lib_init);
	RESET_FAKE(nrf_modem_lib_shutdown);
	RESET_FAKE(nrf_modem_lib_bootloader_init);
	RESET_FAKE(fmfu_fdev_load);
#endif /* CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE */
}

/* This function runs after each completed test */
static void run_after(void *fixture)
{
	ARG_UNUSED(fixture);
}

ZTEST_SUITE(nrf_cloud_fota_common_test, NULL, NULL, run_before, run_after, NULL);

/* Verify that nrf_cloud_fota_is_type_modem returns true for modem-related FOTA types
 * and false for all others, including invalid FOTA types
 */
ZTEST(nrf_cloud_fota_common_test, test_nrf_cloud_fota_is_type_modem)
{
	/* Test range beyond enum values */
	for (enum nrf_cloud_fota_type fota_type = NRF_CLOUD_FOTA_TYPE__FIRST - 1;
	     fota_type <= NRF_CLOUD_FOTA_TYPE__INVALID + 1;
	     ++fota_type) {

		if ((fota_type == NRF_CLOUD_FOTA_MODEM_FULL) ||
		    (fota_type == NRF_CLOUD_FOTA_MODEM_DELTA)) {
			zassert_true(nrf_cloud_fota_is_type_modem(fota_type),
				     "Modem FOTA type not detected");
		} else {
			zassert_false(nrf_cloud_fota_is_type_modem(fota_type),
				      "Non-modem FOTA type detected as modem type");
		}
	}
}

/* Verify that nrf_cloud_fota_is_type_enabled returns the correct value
 * based on the enabled Kconfig options.
 */
ZTEST(nrf_cloud_fota_common_test, test_nrf_cloud_fota_is_type_enabled)
{
	Z_TEST_SKIP_IFNDEF(CONFIG_NRF_CLOUD_FOTA);
	bool ret;

	ret = nrf_cloud_fota_is_type_enabled(NRF_CLOUD_FOTA_APPLICATION);
	zassert_equal(IS_ENABLED(CONFIG_BOOTLOADER_MCUBOOT),
		      ret,
		      "APP FOTA enabled should correspond to the value of: "
		      "CONFIG_BOOTLOADER_MCUBOOT");

	ret = nrf_cloud_fota_is_type_enabled(NRF_CLOUD_FOTA_BOOTLOADER);
	zassert_equal(IS_ENABLED(CONFIG_BOOTLOADER_MCUBOOT) &&
		      IS_ENABLED(CONFIG_BUILD_S1_VARIANT) &&
		      IS_ENABLED(CONFIG_SECURE_BOOT),
		      ret,
		      "BOOT FOTA enabled should correspond to the value of: "
		      "CONFIG_BOOTLOADER_MCUBOOT + CONFIG_BUILD_S1_VARIANT + "
		      "CONFIG_SECURE_BOOT");

	ret = nrf_cloud_fota_is_type_enabled(NRF_CLOUD_FOTA_MODEM_DELTA);
	zassert_equal(IS_ENABLED(CONFIG_NRF_MODEM), ret,
		      "DELTA MODEM FOTA enabled should correspond to the value of: "
		      "CONFIG_NRF_MODEM");

	ret = nrf_cloud_fota_is_type_enabled(NRF_CLOUD_FOTA_MODEM_FULL);
	zassert_equal(IS_ENABLED(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE) &&
		      IS_ENABLED(CONFIG_NRF_MODEM),
		      ret,
		      "FULL MODEM FOTA enabled should correspond to the value of: "
		      "CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE + CONFIG_NRF_MODEM");

	ret = nrf_cloud_fota_is_type_enabled(NRF_CLOUD_FOTA_TYPE__INVALID);
	zassert_false(ret, "return should be false when invalid FOTA type is provided");
}

/* Verify that nrf_cloud_fota_is_type_enabled returns false when no protocols
 * for performing FOTA are enabled.
 */
ZTEST(nrf_cloud_fota_common_test, test_nrf_cloud_fota_is_type_enabled_invalid)
{
	Z_TEST_SKIP_IFDEF(CONFIG_NRF_CLOUD_FOTA);
	Z_TEST_SKIP_IFDEF(CONFIG_NRF_CLOUD_REST);

	zassert_false(nrf_cloud_fota_is_type_enabled(NRF_CLOUD_FOTA_APPLICATION),
		      "return should be false when "
		      "CONFIG_NRF_CLOUD_FOTA and CONFIG_NRF_CLOUD_REST are disabled");
}

/* Verify that nrf_cloud_bootloader_fota_slot_set fails and the BL status flags are not
 * modified when fota_download_s0_active_get fails.
 */
ZTEST(nrf_cloud_fota_common_test, test_nrf_cloud_bootloader_fota_slot_set_get_s0_get_fail)
{
	Z_TEST_SKIP_IFNDEF(CONFIG_FOTA_DOWNLOAD);
	struct nrf_cloud_settings_fota_job job;

	job.bl_flags = NRF_CLOUD_FOTA_BL_STATUS_CLEAR;
	job.type = NRF_CLOUD_FOTA_BOOTLOADER;

	fota_download_s0_active_get_fake.custom_fake = fake_fota_download_s0_active_get__fails;

	int ret = nrf_cloud_bootloader_fota_slot_set(&job);

	zassert_not_equal(0, ret,
			  "return should not be 0 when fota_download_s0_active_get fails");
	zassert_equal(NRF_CLOUD_FOTA_BL_STATUS_CLEAR, job.bl_flags,
		      "bl_flags should be NRF_CLOUD_FOTA_BL_STATUS_CLEAR");
}

/* Verify that nrf_cloud_bootloader_fota_slot_set fails when a NULL parameter is provided. */
ZTEST(nrf_cloud_fota_common_test, test_nrf_cloud_bootloader_fota_slot_fail)
{
	int ret = nrf_cloud_bootloader_fota_slot_set(NULL);

	zassert_equal(-EINVAL, ret, "return should be -EINVAL when job is NULL");
}

/* Verify that nrf_cloud_bootloader_fota_slot_set fails when CONFIG_FOTA_DOWNLOAD is not enabled. */
ZTEST(nrf_cloud_fota_common_test, test_nrf_cloud_bootloader_fota_slot_fota_not_enabled)
{
	Z_TEST_SKIP_IFDEF(CONFIG_FOTA_DOWNLOAD);
	struct nrf_cloud_settings_fota_job job;

	job.bl_flags = NRF_CLOUD_FOTA_BL_STATUS_CLEAR;
	job.type = NRF_CLOUD_FOTA_BOOTLOADER;

	int ret = nrf_cloud_bootloader_fota_slot_set(&job);

	zassert_equal(-ENOTSUP, ret,
		      "return should be -ENOTSUP when CONFIG_FOTA_DOWNLOAD is not enabled");
}

/* Verify that nrf_cloud_bootloader_fota_slot_set returns success with no flag changes
 * for the following conditions:
 *   When a non-BOOT FOTA job is provided.
 *   When a BOOT FOTA job is provided with the s0 set flag already set.
 */
ZTEST(nrf_cloud_fota_common_test, test_nrf_cloud_bootloader_fota_slot_success_no_change)
{
	Z_TEST_SKIP_IFNDEF(CONFIG_FOTA_DOWNLOAD);
	struct nrf_cloud_settings_fota_job job;

	/* Verify no flag changes when a non-BOOT FOTA type is provided */
	job.bl_flags = NRF_CLOUD_FOTA_BL_STATUS_CLEAR;
	job.type = NRF_CLOUD_FOTA_APPLICATION;

	int ret = nrf_cloud_bootloader_fota_slot_set(&job);

	zassert_equal(0, ret,
		      "return should be 0 when not a BOOT type");
	zassert_equal(NRF_CLOUD_FOTA_BL_STATUS_CLEAR, job.bl_flags,
		      "bl_flags should be NRF_CLOUD_FOTA_BL_STATUS_CLEAR");

	/* Verify no flag changes when the s0 set flag is already set for a BOOT FOTA type */
	job.bl_flags = NRF_CLOUD_FOTA_BL_STATUS_S0_FLAG_SET;
	job.type = NRF_CLOUD_FOTA_BOOTLOADER;

	ret = nrf_cloud_bootloader_fota_slot_set(&job);

	zassert_equal(0, ret,
		      "return should be 0 when flag already set");
	zassert_equal(NRF_CLOUD_FOTA_BL_STATUS_S0_FLAG_SET, job.bl_flags,
		      "bl_flags should be NRF_CLOUD_FOTA_BL_STATUS_S0_FLAG_SET");
}

/* Verify that nrf_cloud_bootloader_fota_slot_set returns success and the flags are set correctly
 * when a BOOT FOTA job is provided with the bl_flags cleared.
 * This test checks both states of s0 active.
 */
ZTEST(nrf_cloud_fota_common_test, test_nrf_cloud_bootloader_fota_slot_success)
{
	Z_TEST_SKIP_IFNDEF(CONFIG_FOTA_DOWNLOAD);
	struct nrf_cloud_settings_fota_job job;

	/* Test for s0 active */
	job.bl_flags = NRF_CLOUD_FOTA_BL_STATUS_CLEAR;
	job.type = NRF_CLOUD_FOTA_BOOTLOADER;
	fota_download_s0_active_get_fake.custom_fake = fake_fota_download_s0_active_get__s0_active;

	int ret = nrf_cloud_bootloader_fota_slot_set(&job);

	zassert_equal(0, ret,
		      "return should be 0");
	zassert_equal(NRF_CLOUD_FOTA_BL_STATUS_S0_FLAG_SET|NRF_CLOUD_FOTA_BL_STATUS_S0_WAS_ACTIVE,
		      job.bl_flags,
		      "bl_flags should indicate s0 set and s0 active");

	/* Test for s0 not active (s1 active) */
	job.bl_flags = NRF_CLOUD_FOTA_BL_STATUS_S0_WAS_ACTIVE;
	fota_download_s0_active_get_fake.custom_fake =
		fake_fota_download_s0_active_get__s0_inactive;

	ret = nrf_cloud_bootloader_fota_slot_set(&job);

	zassert_equal(0, ret,
		      "return should be 0");
	zassert_equal(NRF_CLOUD_FOTA_BL_STATUS_S0_FLAG_SET, job.bl_flags,
		      "bl_flags should indicate s0 set and s0 inactive");
}

/* Verify that nrf_cloud_pending_fota_job_process fails for an unknown FOTA job type. */
ZTEST(nrf_cloud_fota_common_test, test_nrf_cloud_pending_fota_job_process_unknwn_type)
{
	struct nrf_cloud_settings_fota_job job;
	bool reboot_required;

	job.validate = NRF_CLOUD_FOTA_VALIDATE_PENDING;
	job.type = NRF_CLOUD_FOTA_TYPE__INVALID + 1;

	int ret = nrf_cloud_pending_fota_job_process(&job, &reboot_required);

	zassert_equal(-ENOENT, ret,
		      "return should be -ENOENT when FOTA type is unknown");
}

/* Verify that nrf_cloud_pending_fota_job_process fails when the function parameters are invalid. */
ZTEST(nrf_cloud_fota_common_test, test_nrf_cloud_pending_fota_job_process_invalid_params)
{
	struct nrf_cloud_settings_fota_job job;
	bool reboot_required;

	int ret = nrf_cloud_pending_fota_job_process(&job, NULL);

	zassert_equal(-EINVAL, ret,
		      "return should be -EINVAL when reboot flag is NULL");

	ret = nrf_cloud_pending_fota_job_process(NULL, &reboot_required);

	zassert_equal(-EINVAL, ret,
		      "return should be -EINVAL when job is NULL");
}

/* Verify that nrf_cloud_pending_fota_job_process fails when the job parameters are invalid. */
ZTEST(nrf_cloud_fota_common_test, test_nrf_cloud_pending_fota_job_process_job_not_applicable)
{
	struct nrf_cloud_settings_fota_job job;
	bool reboot_required;

	job.validate = NRF_CLOUD_FOTA_VALIDATE_NONE;
	job.type = NRF_CLOUD_FOTA_MODEM_DELTA;

	int ret = nrf_cloud_pending_fota_job_process(&job, &reboot_required);

	zassert_equal(-ENODEV, ret,
		      "return should be -ENODEV when job is not NRF_CLOUD_FOTA_VALIDATE_PENDING");

	job.validate = NRF_CLOUD_FOTA_VALIDATE_PENDING;
	job.type = NRF_CLOUD_FOTA_TYPE__INVALID;

	ret = nrf_cloud_pending_fota_job_process(&job, &reboot_required);

	zassert_equal(-ENODEV, ret,
		      "return should be -ENODEV when job type is NRF_CLOUD_FOTA_TYPE__INVALID");
}

/* Verify that nrf_cloud_pending_fota_job_process succeeds when a pending
 * APP FOTA validation PASSES.
 */
ZTEST(nrf_cloud_fota_common_test, test_nrf_cloud_pending_fota_job_process_app_pass)
{
	Z_TEST_SKIP_IFNDEF(CONFIG_MCUBOOT_IMG_MANAGER);
	struct nrf_cloud_settings_fota_job job;
	bool reboot_required;

	job.validate = NRF_CLOUD_FOTA_VALIDATE_PENDING;
	job.type = NRF_CLOUD_FOTA_APPLICATION;

	boot_is_img_confirmed_fake.custom_fake = fake_boot_is_img_confirmed__false;
	boot_write_img_confirmed_fake.custom_fake = fake_boot_write_img_confirmed__succeeds;

	int ret = nrf_cloud_pending_fota_job_process(&job, &reboot_required);

	zassert_equal(0, ret, "return should be 0 when app FOTA succeeds");
	zassert_equal(NRF_CLOUD_FOTA_VALIDATE_PASS, job.validate,
		      "validate status should be PASS on success");
}

/* Verify that nrf_cloud_pending_fota_job_process succeeds when a pending
 * APP FOTA validation FAILS due to a boot_write_img_confirmed failure.
 */
ZTEST(nrf_cloud_fota_common_test, test_nrf_cloud_pending_fota_job_process_app_fail)
{
	Z_TEST_SKIP_IFNDEF(CONFIG_MCUBOOT_IMG_MANAGER);
	struct nrf_cloud_settings_fota_job job;
	bool reboot_required = false;

	job.validate = NRF_CLOUD_FOTA_VALIDATE_PENDING;
	job.type = NRF_CLOUD_FOTA_APPLICATION;

	boot_is_img_confirmed_fake.custom_fake = fake_boot_is_img_confirmed__false;
	boot_write_img_confirmed_fake.custom_fake = fake_boot_write_img_confirmed__fails;

	int ret = nrf_cloud_pending_fota_job_process(&job, &reboot_required);

	zassert_equal(0, ret, "return should be 0 when app FOTA is processed as failure");
	zassert_equal(true, reboot_required,
		      "reboot_required should be true when app FOTA is processed as failure");
	zassert_equal(NRF_CLOUD_FOTA_VALIDATE_FAIL, job.validate,
		      "validate status should be FAIL when app FOTA is processed as failure");
}

/* Verify that nrf_cloud_pending_fota_job_process succeeds for a pending APP FOTA job and
 * that the validate status is set to UNKNOWN when the image is already confirmed.
 */
ZTEST(nrf_cloud_fota_common_test, test_nrf_cloud_pending_fota_job_process_app_unknown)
{
	Z_TEST_SKIP_IFNDEF(CONFIG_MCUBOOT_IMG_MANAGER);
	struct nrf_cloud_settings_fota_job job;
	bool reboot_required;

	job.validate = NRF_CLOUD_FOTA_VALIDATE_PENDING;
	job.type = NRF_CLOUD_FOTA_APPLICATION;

	boot_is_img_confirmed_fake.custom_fake = fake_boot_is_img_confirmed__true;

	int ret = nrf_cloud_pending_fota_job_process(&job, &reboot_required);

	zassert_equal(0, ret, "return should be 0 when app FOTA is already confirmed");
	zassert_equal(NRF_CLOUD_FOTA_VALIDATE_UNKNOWN, job.validate,
		      "validate status should be UNKNOWN when write is already confirmed");
}

/* Verify that nrf_cloud_pending_fota_job_process succeeds and sets the job validation status
 * to UNKNOWN when provided a pending APP FOTA job and CONFIG_MCUBOOT_IMG_MANAGER is not enabled.
 */
ZTEST(nrf_cloud_fota_common_test, test_nrf_cloud_pending_fota_job_process_app_unknwn_no_img_mgr)
{
	Z_TEST_SKIP_IFDEF(CONFIG_MCUBOOT_IMG_MANAGER);
	struct nrf_cloud_settings_fota_job job;
	bool reboot_required;

	job.validate = NRF_CLOUD_FOTA_VALIDATE_PENDING;
	job.type = NRF_CLOUD_FOTA_APPLICATION;

	int ret = nrf_cloud_pending_fota_job_process(&job, &reboot_required);

	zassert_equal(0, ret, "return should be 0 when app FOTA is already confirmed");
	zassert_equal(NRF_CLOUD_FOTA_VALIDATE_UNKNOWN, job.validate,
		      "validate status should be UNKNOWN when CONFIG_MCUBOOT_IMG_MANAGER=n");
}

/* Verify that nrf_cloud_pending_fota_job_process succeeds when a pending
 * BOOT FOTA is processed with the REBOOTED BL flag not set.
 * The REBOOTED BL flag should become set and the reboot_required flag should become true.
 */
ZTEST(nrf_cloud_fota_common_test, test_nrf_cloud_pending_fota_job_process_boot_reboot)
{
	struct nrf_cloud_settings_fota_job job;
	bool reboot_required = false;

	job.type = NRF_CLOUD_FOTA_BOOTLOADER;
	job.validate = NRF_CLOUD_FOTA_VALIDATE_PENDING;

	/* Clear all flags, but specifically NRF_CLOUD_FOTA_BL_STATUS_REBOOTED */
	job.bl_flags = NRF_CLOUD_FOTA_BL_STATUS_CLEAR;

	int ret = nrf_cloud_pending_fota_job_process(&job, &reboot_required);

	zassert_equal(0, ret,
		      "return should be zero on pending BOOT FOTA with no flags set");
	zassert_true(reboot_required,
		     "reboot_required should be true when REBOOTED flag is not set");
	zassert_equal(NRF_CLOUD_FOTA_BL_STATUS_REBOOTED,
		      job.bl_flags & NRF_CLOUD_FOTA_BL_STATUS_REBOOTED,
		      "REBOOTED flag should be set when reboot_required is indicated");
}

/* Verify that nrf_cloud_pending_fota_job_process succeeds when a pending
 * BOOT FOTA is processed with the REBOOTED BL flag set and CONFIG_FOTA_DOWNLOAD is not enabled.
 * The bl_flags should be unchanged, the reboot_required flag should be false/unchanged and the
 * validate status should become UNKNOWN.
 */
ZTEST(nrf_cloud_fota_common_test, test_nrf_cloud_pending_fota_job_process_boot_unknwn_no_fota_dl)
{
	Z_TEST_SKIP_IFDEF(CONFIG_FOTA_DOWNLOAD);

	struct nrf_cloud_settings_fota_job job;
	bool reboot_required = false;

	job.type = NRF_CLOUD_FOTA_BOOTLOADER;
	job.validate = NRF_CLOUD_FOTA_VALIDATE_PENDING;
	job.bl_flags = NRF_CLOUD_FOTA_BL_STATUS_REBOOTED;

	int ret = nrf_cloud_pending_fota_job_process(&job, &reboot_required);

	zassert_equal(0, ret,
		      "return should be zero on pending BOOT FOTA with REBOOTED set");
	zassert_false(reboot_required,
		      "reboot_required should be false when REBOOTED flag is set");
	zassert_equal(NRF_CLOUD_FOTA_BL_STATUS_REBOOTED,
		      job.bl_flags,
		      "bl_flags flags should be unchanged when CONFIG_FOTA_DOWNLOAD=n");
	zassert_equal(NRF_CLOUD_FOTA_VALIDATE_UNKNOWN, job.validate,
		      "validate status should be UNKNOWN when CONFIG_FOTA_DOWNLOAD=n");
}

/* Verify that nrf_cloud_pending_fota_job_process succeeds when a pending
 * BOOT FOTA is processed with the REBOOTED BL flag set and the S0_SET BL flag not-set.
 * The bl_flags should be unchanged, the reboot_required flag should be false/unchanged and the
 * validate status should become UNKNOWN.
 */
ZTEST(nrf_cloud_fota_common_test, test_nrf_cloud_pending_fota_job_process_boot_unknwn_s0_flag_clr)
{
	Z_TEST_SKIP_IFNDEF(CONFIG_FOTA_DOWNLOAD);

	struct nrf_cloud_settings_fota_job job;
	bool reboot_required = false;

	job.type = NRF_CLOUD_FOTA_BOOTLOADER;
	job.validate = NRF_CLOUD_FOTA_VALIDATE_PENDING;
	/* Only set rebooted flag, NRF_CLOUD_FOTA_BL_STATUS_S0_FLAG_SET should be cleared */
	job.bl_flags = NRF_CLOUD_FOTA_BL_STATUS_REBOOTED;

	int ret = nrf_cloud_pending_fota_job_process(&job, &reboot_required);

	zassert_equal(0, ret,
		      "return should be zero on pending BOOT FOTA with REBOOTED set");
	zassert_false(reboot_required,
		      "reboot_required should be false when REBOOTED flag is set");
	zassert_equal(NRF_CLOUD_FOTA_BL_STATUS_REBOOTED,
		      job.bl_flags,
		      "bl_flags flags should be unchanged when REBOOTED is set");
	zassert_equal(NRF_CLOUD_FOTA_VALIDATE_UNKNOWN, job.validate,
		      "validate status should be UNKNOWN when S0_FLAG_SET is not set");
}

/* Verify that nrf_cloud_pending_fota_job_process succeeds when a pending
 * BOOT FOTA is processed with the REBOOTED BL flag set and the S0_SET BL flag set.
 * All three validation results are tested:
 *   FAIL: s0 remains inactive after reboot.
 *   PASS: s0 was active before reboot and becomes inactive after reboot.
 *   UNKNOWN: failure getting active slot (fota_download_s0_active_get fails)
 */
ZTEST(nrf_cloud_fota_common_test, test_nrf_cloud_pending_fota_job_process_boot_s0_flag_set)
{
	Z_TEST_SKIP_IFNDEF(CONFIG_FOTA_DOWNLOAD);

	int ret;
	enum nrf_cloud_fota_bootloader_status_flags flags;
	struct nrf_cloud_settings_fota_job job;
	bool reboot_required = false;

	/* Use this s0 inactive fake for the entire test */
	fota_download_s0_active_get_fake.custom_fake =
		fake_fota_download_s0_active_get__s0_inactive;

	/* Test for validate FAIL */
	job.type = NRF_CLOUD_FOTA_BOOTLOADER;
	job.validate = NRF_CLOUD_FOTA_VALIDATE_PENDING;
	/* Simulate a post-reboot call with S0 inactive before and after */
	flags = NRF_CLOUD_FOTA_BL_STATUS_REBOOTED | NRF_CLOUD_FOTA_BL_STATUS_S0_FLAG_SET;
	job.bl_flags = flags;

	ret = nrf_cloud_pending_fota_job_process(&job, &reboot_required);

	zassert_equal(0, ret,
		      "return should be zero on pending BOOT FOTA with REBOOTED set");
	zassert_false(reboot_required,
		      "reboot_required should be false when REBOOTED flag is set");
	zassert_equal(flags, job.bl_flags,
		      "bl_flags flags should be unchanged when REBOOTED is set");
	zassert_equal(NRF_CLOUD_FOTA_VALIDATE_FAIL, job.validate,
		      "validate status should be FAIL when s0 remains inactive");

	/* Test for validate PASS */
	job.type = NRF_CLOUD_FOTA_BOOTLOADER;
	job.validate = NRF_CLOUD_FOTA_VALIDATE_PENDING;
	/* Simulate a post-reboot call with s0 active before and s0 inactive after */
	flags = NRF_CLOUD_FOTA_BL_STATUS_REBOOTED | NRF_CLOUD_FOTA_BL_STATUS_S0_FLAG_SET |
		NRF_CLOUD_FOTA_BL_STATUS_S0_WAS_ACTIVE;
	job.bl_flags = flags;

	ret = nrf_cloud_pending_fota_job_process(&job, &reboot_required);

	zassert_equal(0, ret,
		      "return should be zero on pending BOOT FOTA with REBOOTED set");
	zassert_false(reboot_required,
		      "reboot_required should be false when REBOOTED flag is set");
	zassert_equal(flags, job.bl_flags,
		      "bl_flags flags should be unchanged when REBOOTED is not set");
	zassert_equal(NRF_CLOUD_FOTA_VALIDATE_PASS, job.validate,
		      "validate status should be PASS when s0 active changes");

	/* Test for validate UNKNOWN */
	job.type = NRF_CLOUD_FOTA_BOOTLOADER;
	job.validate = NRF_CLOUD_FOTA_VALIDATE_PENDING;
	flags = NRF_CLOUD_FOTA_BL_STATUS_REBOOTED | NRF_CLOUD_FOTA_BL_STATUS_S0_FLAG_SET;
	job.bl_flags = flags;

	/* Test when fota_download_s0_active_get fails */
	fota_download_s0_active_get_fake.custom_fake = fake_fota_download_s0_active_get__fails;

	ret = nrf_cloud_pending_fota_job_process(&job, &reboot_required);

	zassert_equal(0, ret,
		      "return should be zero on pending BOOT FOTA with REBOOTED set");
	zassert_false(reboot_required,
		      "reboot_required should be false when REBOOTED flag is set");
	zassert_equal(flags, job.bl_flags,
		      "bl_flags flags should be unchanged when REBOOTED is not set");
	zassert_equal(NRF_CLOUD_FOTA_VALIDATE_UNKNOWN, job.validate,
		      "validate status should be UNKNOWN when fota_download_s0_active_get fails");
}

/* Verify that nrf_cloud_fota_fmfu_dev_set returns failure when the function parameter is NULL. */
ZTEST(nrf_cloud_fota_common_test, test_00_nrf_cloud_fota_fmfu_dev_set_null_fdev)
{
	Z_TEST_SKIP_IFNDEF(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE);
	Z_TEST_SKIP_IFDEF(CONFIG_DFU_TARGET_FULL_MODEM_USE_EXT_PARTITION);

#if defined(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE)
	int ret = nrf_cloud_fota_fmfu_dev_set(NULL);

	zassert_equal(-EINVAL, ret, "return should be -EINVAL when NULL parameter is provided");
#endif
}

/* Verify that nrf_cloud_fota_fmfu_dev_set returns failure when the flash device is NULL
 * and CONFIG_DFU_TARGET_FULL_MODEM_USE_EXT_PARTITION=n
 */
ZTEST(nrf_cloud_fota_common_test, test_01_nrf_cloud_fota_fmfu_dev_set_null_device)
{
	Z_TEST_SKIP_IFNDEF(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE);
	Z_TEST_SKIP_IFDEF(CONFIG_DFU_TARGET_FULL_MODEM_USE_EXT_PARTITION);

#if defined(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE)
	/* Provide a NULL flash device */
	struct dfu_target_fmfu_fdev fmfu_dev_inf = { .dev = NULL };
	int ret = nrf_cloud_fota_fmfu_dev_set(&fmfu_dev_inf);

	zassert_equal(-ENODEV, ret, "return should be -ENODEV when NULL device is provided");
#endif
}

/* Verify that nrf_cloud_fota_fmfu_dev_set returns failure when the flash device is not ready
 * and CONFIG_DFU_TARGET_FULL_MODEM_USE_EXT_PARTITION=n
 */
ZTEST(nrf_cloud_fota_common_test, test_02_nrf_cloud_fota_fmfu_dev_set_fail_dev_not_ready)
{
	Z_TEST_SKIP_IFNDEF(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE);
	Z_TEST_SKIP_IFDEF(CONFIG_DFU_TARGET_FULL_MODEM_USE_EXT_PARTITION);

#if defined(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE)
	int ret;

	/* Provide a fake flash device that is not ready */
	struct device_state state = { .init_res = -1, .initialized = false };
	struct device flash_dev = { .state = &state };
	struct dfu_target_fmfu_fdev fmfu_dev_inf = { .dev = &flash_dev };

	dfu_target_full_modem_cfg_fake.custom_fake =
		fake_dfu_target_full_modem_cfg__succeeds;
	dfu_target_full_modem_fdev_get_fake.custom_fake =
		fake_dfu_target_full_modem_fdev_get__succeeds;

	ret = nrf_cloud_fota_fmfu_dev_set(&fmfu_dev_inf);
	zassert_not_equal(0, ret,
			  "return should not be 0 when flash device is not ready");
#endif
}

/* Verify that nrf_cloud_fota_fmfu_dev_set returns failure when dfu_target_full_modem_cfg fails. */
ZTEST(nrf_cloud_fota_common_test, test_03_nrf_cloud_fota_fmfu_dev_set_cfg_fail)
{
	Z_TEST_SKIP_IFNDEF(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE);

#if defined(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE)
	int ret;

	/* Provide a fake flash device in the ready state */
	struct device_state state = { .init_res = 0, .initialized = true };
	struct device flash_dev = { .state = &state };
	struct dfu_target_fmfu_fdev fmfu_dev_inf = { .dev = &flash_dev };

	dfu_target_full_modem_cfg_fake.custom_fake =
		fake_dfu_target_full_modem_cfg__fails;
	dfu_target_full_modem_fdev_get_fake.custom_fake =
		fake_dfu_target_full_modem_fdev_get__succeeds;

	ret = nrf_cloud_fota_fmfu_dev_set(&fmfu_dev_inf);
	zassert_not_equal(0, ret, "return should not be 0 when dfu_target_full_modem_cfg fails");
#endif
}

/* Verify that nrf_cloud_fota_fmfu_dev_set returns failure when dfu_target_full_modem_fdev_get
 * fails.
 */
ZTEST(nrf_cloud_fota_common_test, test_04_nrf_cloud_fota_fmfu_dev_set_fail_fdev_get_fail)
{
	Z_TEST_SKIP_IFNDEF(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE);

#if defined(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE)
	int ret;

	/* Provide a fake flash device in the ready state */
	struct device_state state = { .init_res = 0, .initialized = true };
	struct device flash_dev = { .state = &state };
	struct dfu_target_fmfu_fdev fmfu_dev_inf = { .dev = &flash_dev };

	dfu_target_full_modem_cfg_fake.custom_fake =
		fake_dfu_target_full_modem_cfg__succeeds;
	dfu_target_full_modem_fdev_get_fake.custom_fake =
		fake_dfu_target_full_modem_fdev_get__fails;

	ret = nrf_cloud_fota_fmfu_dev_set(&fmfu_dev_inf);
	zassert_not_equal(0, ret,
			  "return should not be 0 when dfu_target_full_modem_fdev_get fails");
#endif
}

/* Verify that nrf_cloud_fota_fmfu_apply returns failure when the external flash device is not set.
 * This test must be called before nrf_cloud_fota_fmfu_dev_set executes successfully
 */
ZTEST(nrf_cloud_fota_common_test, test_05_nrf_cloud_fota_fmfu_apply_fail_dev_not_set)
{
	Z_TEST_SKIP_IFNDEF(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE);

#if defined(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE)
	int ret;

	nrf_modem_lib_shutdown_fake.custom_fake = nrf_modem_lib_shutdown__succeeds;
	nrf_modem_lib_bootloader_init_fake.custom_fake = nrf_modem_lib_bootloader_init__succeeds;
	fmfu_fdev_load_fake.custom_fake = fmfu_fdev_load__succeeds;

	ret = nrf_cloud_fota_fmfu_apply();
	zassert_equal(-EACCES, ret, "return should be -EACCES when flash device is not set");
#endif
}

/* Verify that nrf_cloud_pending_fota_job_process succeeds when a pending
 * FMFU FOTA validation FAILS because the external flash device is not set.
 * The reboot flag should become true.
 * This test must be called before nrf_cloud_fota_fmfu_dev_set executes successfully.
 */
ZTEST(nrf_cloud_fota_common_test, test_06_nrf_cloud_pending_fota_job_process_fmfu_validate_fail)
{
	Z_TEST_SKIP_IFNDEF(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE);

#if defined(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE)
	int ret;
	bool reboot = false;
	struct nrf_cloud_settings_fota_job job = {
		.validate = NRF_CLOUD_FOTA_VALIDATE_PENDING,
		.type = NRF_CLOUD_FOTA_MODEM_FULL
	};

	ret = nrf_cloud_pending_fota_job_process(&job, &reboot);

	zassert_equal(0, ret, "return should be 0 after FMFU job is processed");
	zassert_equal(true, reboot, "reboot should be true when FMFU job is processed");
	/* nrf_cloud_fota_fmfu_dev_set has not yet successfully executed */
	zassert_equal(NRF_CLOUD_FOTA_VALIDATE_FAIL,
		      job.validate,
		      "validate status should be FAIL when flash device is not set");
#endif
}

/* Verify that nrf_cloud_fota_fmfu_dev_set succeeds when the flash device is
 * valid/ready and the dfu_target functions succeed.
 * Also, verify that when nrf_cloud_fota_fmfu_dev_set is called a second time, it
 * returns 1.
 * This PASS case for nrf_cloud_fota_fmfu_dev_set should be executed last due to static
 * flag which tracks if the FMFU device has been set successfully.
 */
ZTEST(nrf_cloud_fota_common_test, test_07_nrf_cloud_fota_fmfu_dev_set_pass)
{
	Z_TEST_SKIP_IFNDEF(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE);

#if defined(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE)
	int ret;

	/* Provide a fake flash device in the ready state */
	struct device_state state = { .init_res = 0, .initialized = true };
	struct device flash_dev = { .state = &state };
	struct dfu_target_fmfu_fdev fmfu_dev_inf = { .dev = &flash_dev };

	dfu_target_full_modem_cfg_fake.custom_fake =
		fake_dfu_target_full_modem_cfg__succeeds;
	dfu_target_full_modem_fdev_get_fake.custom_fake =
		fake_dfu_target_full_modem_fdev_get__succeeds;

	ret = nrf_cloud_fota_fmfu_dev_set(&fmfu_dev_inf);
	zassert_equal(0, ret, "return should be 0 when device is not yet set");

	ret = nrf_cloud_fota_fmfu_dev_set(&fmfu_dev_inf);
	zassert_equal(1, ret, "return should be 1 when device is already set");
#endif
}

/* Verify that nrf_cloud_pending_fota_job_process succeeds when a pending
 * FMFU FOTA validation PASSES.
 * The reboot flag should become true.
 * Must be called after nrf_cloud_fota_fmfu_dev_set() is successful.
 */
ZTEST(nrf_cloud_fota_common_test, test_08_nrf_cloud_pending_fota_job_process_fmfu_pass)
{
	Z_TEST_SKIP_IFNDEF(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE);

#if defined(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE)
	int ret;
	bool reboot = false;
	struct nrf_cloud_settings_fota_job job = {
		.validate = NRF_CLOUD_FOTA_VALIDATE_PENDING,
		.type = NRF_CLOUD_FOTA_MODEM_FULL
	};

	/* Set fakes so that nrf_cloud_fota_fmfu_apply() succeeds */
	nrf_modem_lib_shutdown_fake.custom_fake = nrf_modem_lib_shutdown__succeeds;
	nrf_modem_lib_bootloader_init_fake.custom_fake = nrf_modem_lib_bootloader_init__succeeds;
	fmfu_fdev_load_fake.custom_fake = fmfu_fdev_load__succeeds;

	ret = nrf_cloud_pending_fota_job_process(&job, &reboot);

	zassert_equal(0, ret, "return should be 0 when FMFU job is processed");
	zassert_equal(true, reboot, "reboot should be true when FMFU job is processed");
	zassert_equal(NRF_CLOUD_FOTA_VALIDATE_PASS,
		      job.validate,
		      "validate status should be PASS when FMFU job is processed successfully");
#endif
}

/* Verify that nrf_cloud_pending_fota_job_process fails when CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE
 * is not enabled.
 */
ZTEST(nrf_cloud_fota_common_test, test_nrf_cloud_pending_fota_job_process_fmfu_not_enabled)
{
	Z_TEST_SKIP_IFDEF(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE);

	int ret;
	bool reboot = false;
	struct nrf_cloud_settings_fota_job job = {
		.validate = NRF_CLOUD_FOTA_VALIDATE_PENDING,
		.type = NRF_CLOUD_FOTA_MODEM_FULL
	};

	ret = nrf_cloud_pending_fota_job_process(&job, &reboot);

	zassert_equal(-ESRCH, ret, "return should be -ESRCH when FMFU is not enabled");
	zassert_equal(NRF_CLOUD_FOTA_VALIDATE_FAIL,
		      job.validate,
		      "validate status should be FAIL when FMFU is not enabled");
}

/* Verify that nrf_cloud_fota_fmfu_apply succeeds. */
ZTEST(nrf_cloud_fota_common_test, test_nrf_cloud_fota_fmfu_apply_pass)
{
	Z_TEST_SKIP_IFNDEF(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE);

#if defined(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE)
	int ret;

	nrf_modem_lib_shutdown_fake.custom_fake = nrf_modem_lib_shutdown__succeeds;
	nrf_modem_lib_bootloader_init_fake.custom_fake = nrf_modem_lib_bootloader_init__succeeds;
	fmfu_fdev_load_fake.custom_fake = fmfu_fdev_load__succeeds;

	ret = nrf_cloud_fota_fmfu_apply();
	zassert_equal(0, ret, "return should be 0 when FMFU succeeds");
#endif
}

/* Verify that nrf_cloud_fota_fmfu_apply fails when nrf_modem_lib_shutdown fails. */
ZTEST(nrf_cloud_fota_common_test, test_nrf_cloud_fota_fmfu_apply_fail_shutdown_fail)
{
	Z_TEST_SKIP_IFNDEF(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE);

#if defined(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE)
	int ret;

	nrf_modem_lib_shutdown_fake.custom_fake = nrf_modem_lib_shutdown__fails;

	ret = nrf_cloud_fota_fmfu_apply();
	zassert_not_equal(0, ret, "return should not be 0 when when nrf_modem_lib_shutdown fails");
#endif
}

/* Verify that nrf_cloud_fota_fmfu_apply fails when nrf_modem_lib_bootloader_init fails. */
ZTEST(nrf_cloud_fota_common_test, test_nrf_cloud_fota_fmfu_apply_fail_bl_init_fail)
{
	Z_TEST_SKIP_IFNDEF(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE);

#if defined(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE)
	int ret;

	nrf_modem_lib_shutdown_fake.custom_fake = nrf_modem_lib_shutdown__succeeds;
	nrf_modem_lib_bootloader_init_fake.custom_fake = nrf_modem_lib_bootloader_init__fails;

	ret = nrf_cloud_fota_fmfu_apply();
	zassert_not_equal(0, ret,
			  "return should not be 0 when when nrf_modem_lib_bootloader_init fails");
#endif
}

/* Verify that nrf_cloud_fota_fmfu_apply fails when fmfu_fdev_load fails. */
ZTEST(nrf_cloud_fota_common_test, test_nrf_cloud_fota_fmfu_apply_fail_bl_fdev_load_fail)
{
	Z_TEST_SKIP_IFNDEF(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE);

#if defined(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE)
	int ret;

	nrf_modem_lib_shutdown_fake.custom_fake = nrf_modem_lib_shutdown__succeeds;
	nrf_modem_lib_bootloader_init_fake.custom_fake = nrf_modem_lib_bootloader_init__succeeds;
	fmfu_fdev_load_fake.custom_fake = fmfu_fdev_load__fails;

	ret = nrf_cloud_fota_fmfu_apply();
	zassert_not_equal(0, ret, "return should not be 0 when when fmfu_fdev_load fails");
#endif
}
