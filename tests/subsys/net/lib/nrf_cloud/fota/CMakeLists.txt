#
# Copyright (c) 2022 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(nrf_cloud_fota_test)
set(NRF_SDK_DIR ${ZEPHYR_BASE}/../nrf)
cmake_path(NORMAL_PATH NRF_SDK_DIR)

FILE(GLOB app_sources src/main.c)
target_sources(app PRIVATE ${app_sources})

target_sources(app
	PRIVATE
	${ZEPHYR_NRF_MODULE_DIR}/subsys/net/lib/nrf_cloud/src/nrf_cloud_fota.c
)

target_include_directories(app
	PRIVATE
	src
	${ZEPHYR_NRF_MODULE_DIR}/subsys/net/lib/nrf_cloud/include
	${ZEPHYR_BASE}/subsys/testsuite/include
)

set_source_files_properties(
	${ZEPHYR_BASE}/subsys/net/lib/mqtt/mqtt.c
	PROPERTIES HEADER_FILE_ONLY ON
)

set_source_files_properties(
	${NRF_SDK_DIR}/subsys/net/lib/fota_download/src/fota_download.c
	PROPERTIES HEADER_FILE_ONLY ON
)