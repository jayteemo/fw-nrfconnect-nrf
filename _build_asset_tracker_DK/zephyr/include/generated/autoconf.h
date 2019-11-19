/* Generated by Kconfiglib (https://github.com/ulfalizer/Kconfiglib) */
#define CONFIG_USE_UI_MODULE 1
#define CONFIG_UI_LOG_LEVEL_INF 1
#define CONFIG_UI_LOG_LEVEL 3
#define CONFIG_GPS_USE_EXTERNAL 1
#define CONFIG_GPS_CONTROL 1
#define CONFIG_GPS_CONTROL_ON_LONG_PRESS 1
#define CONFIG_GPS_CONTROL_PSM_ENABLE_ON_START 1
#define CONFIG_GPS_CONTROL_FIRST_FIX_CHECK_DELAY 10
#define CONFIG_GPS_CONTROL_FIX_CHECK_INTERVAL 30
#define CONFIG_GPS_CONTROL_FIX_TRY_TIME 360
#define CONFIG_GPS_CONTROL_FIX_COUNT 3
#define CONFIG_GPS_CONTROL_MAX_FAILED_FIX_ATTEMPTS 3
#define CONFIG_GPS_CONTROL_LOG_LEVEL_INF 1
#define CONFIG_GPS_CONTROL_LOG_LEVEL 3
#define CONFIG_GPS_DEV_NAME "NRF9160_GPS"
#define CONFIG_GPS_SIM_TRIGGER_TIMER_MSEC 2000
#define CONFIG_HOLD_TIME_RSRP 60
#define CONFIG_ACCEL_USE_SIM 1
#define CONFIG_ACCEL_DEV_NAME "SENSOR_SIM"
#define CONFIG_ACCEL_TRIGGER 1
#define CONFIG_FLIP_INPUT 3
#define CONFIG_ACCEL_CALIBRATION_ITERATIONS 0
#define CONFIG_ACCEL_ITERATIONS 1
#define CONFIG_MQTT_KEEPALIVE 360
#define CONFIG_CLOUD_BUTTON_INPUT 1
#define CONFIG_CLOUD_WAIT_DURATION 30
#define CONFIG_CLOUD_FOTA_APP 1
#define CONFIG_CLOUD_FOTA_MODEM 1
#define CONFIG_BOSCH_BSEC_LIBRARY_PATH "/Users/justin/Github/FORKS/fsm_cleanup/zephyr/../nrf/ext/BSEC_1.4.7.4_Generic_Release"
#define CONFIG_ENVIRONMENT_DATA_SEND_INTERVAL 30
#define CONFIG_ENVIRONMENT_DATA_BACKOFF_TIME 20
#define CONFIG_TEMP_USE_SIM 1
#define CONFIG_TEMP_DEV_NAME "SENSOR_SIM"
#define CONFIG_TEMP_TRIGGER 1
#define CONFIG_TEMP_SIM_BUTTON 3
#define CONFIG_USE_AT_HOST 1
#define CONFIG_DFU_TARGET 1
#define CONFIG_DFU_TARGET_MCUBOOT 1
#define CONFIG_DFU_TARGET_MODEM 1
#define CONFIG_DFU_TARGET_LOG_LEVEL_INF 1
#define CONFIG_DFU_TARGET_LOG_LEVEL 3
#define CONFIG_NRF_CLOUD 1
#define CONFIG_NRF_CLOUD_SEC_TAG 16842753
#define CONFIG_NRF_CLOUD_HOST_NAME "a2n7tk1kp18wix-ats.iot.us-east-1.amazonaws.com"
#define CONFIG_NRF_CLOUD_PORT 8883
#define CONFIG_NRF_CLOUD_MQTT_MESSAGE_BUFFER_LEN 256
#define CONFIG_NRF_CLOUD_MQTT_PAYLOAD_BUFFER_LEN 2048
#define CONFIG_NRF_CLOUD_LOG_LEVEL_DBG 1
#define CONFIG_NRF_CLOUD_LOG_LEVEL 4
#define CONFIG_DOWNLOAD_CLIENT 1
#define CONFIG_DOWNLOAD_CLIENT_MAX_FRAGMENT_SIZE 4096
#define CONFIG_DOWNLOAD_CLIENT_MAX_RESPONSE_SIZE 4096
#define CONFIG_DOWNLOAD_CLIENT_STACK_SIZE 4096
#define CONFIG_DOWNLOAD_CLIENT_SOCK_TIMEOUT_MS -1
#define CONFIG_DOWNLOAD_CLIENT_LOG_LEVEL_INF 1
#define CONFIG_DOWNLOAD_CLIENT_LOG_LEVEL 3
#define CONFIG_FOTA_DOWNLOAD 1
#define CONFIG_FOTA_SOCKET_RETRIES 2
#define CONFIG_FOTA_DOWNLOAD_LOG_LEVEL_INF 1
#define CONFIG_FOTA_DOWNLOAD_LOG_LEVEL 3
#define CONFIG_AWS_JOBS 1
#define CONFIG_CLIENT_ID_MAX_LEN 64
#define CONFIG_UPDATE_JOB_PAYLOAD_LEN 1350
#define CONFIG_AWS_JOBS_LOG_LEVEL_DBG 1
#define CONFIG_AWS_JOBS_LOG_LEVEL 4
#define CONFIG_AWS_FOTA 1
#define CONFIG_AWS_FOTA_VERSION_STRING_MAX_LEN 128
#define CONFIG_AWS_FOTA_PAYLOAD_SIZE 1350
#define CONFIG_AWS_FOTA_HOSTNAME_MAX_LEN 255
#define CONFIG_AWS_FOTA_FILE_PATH_MAX_LEN 255
#define CONFIG_AWS_FOTA_LOG_LEVEL_DBG 1
#define CONFIG_AWS_FOTA_LOG_LEVEL 4
#define CONFIG_CLOUD_API 1
#define CONFIG_SPM 1
#define CONFIG_SPM_BUILD_STRATEGY_FROM_SOURCE 1
#define CONFIG_ARM_ENTRY_VENEERS_LIB_NAME "libspmsecureentries.a"
#define CONFIG_FW_INFO 1
#define CONFIG_FW_VALIDATION_METADATA_OFFSET 0
#define CONFIG_FW_INFO_OFFSET 0x200
#define CONFIG_FW_INFO_VERSION 1
#define CONFIG_FW_INFO_MAGIC_COMMON 0x281ee6de
#define CONFIG_FW_INFO_MAGIC_FIRMWARE_INFO 0x8fcebb4c
#define CONFIG_FW_INFO_MAGIC_ABI_GETTER_INFO 0x2ed9a4c5
#define CONFIG_FW_INFO_MAGIC_ABI_INFO 0xb845acea
#define CONFIG_FW_INFO_HARDWARE_ID 91
#define CONFIG_FW_INFO_CRYPTO_ID 0
#define CONFIG_FW_INFO_MAGIC_COMPATIBILITY_ID 0
#define CONFIG_FW_INFO_MAGIC_LEN 12
#define CONFIG_BSD_LIBRARY 1
#define CONFIG_BSD_LIBRARY_SYS_INIT 1
#define CONFIG_AT_NOTIF 1
#define CONFIG_AT_NOTIF_SYS_INIT 1
#define CONFIG_AT_NOTIF_LOG_LEVEL_INF 1
#define CONFIG_AT_NOTIF_LOG_LEVEL 3
#define CONFIG_AT_HOST_LIBRARY 1
#define CONFIG_AT_HOST_UART_0 1
#define CONFIG_AT_HOST_UART 0
#define CONFIG_AT_HOST_UART_INIT_TIMEOUT 500
#define CONFIG_CR_TERMINATION 1
#define CONFIG_AT_HOST_TERMINATION 1
#define CONFIG_AT_HOST_CMD_MAX_LEN 4096
#define CONFIG_AT_HOST_THREAD_PRIO 10
#define CONFIG_AT_HOST_LOG_LEVEL_INF 1
#define CONFIG_AT_HOST_LOG_LEVEL 3
#define CONFIG_DK_LIBRARY 1
#define CONFIG_DK_LIBRARY_BUTTON_SCAN_INTERVAL 10
#define CONFIG_DK_LIBRARY_INVERT_BUTTONS 1
#define CONFIG_DK_LIBRARY_LOG_LEVEL_INF 1
#define CONFIG_DK_LIBRARY_LOG_LEVEL 3
#define CONFIG_AT_CMD_PARSER 1
#define CONFIG_MODEM_INFO 1
#define CONFIG_MODEM_INFO_MAX_AT_PARAMS_RSP 10
#define CONFIG_MODEM_INFO_BUFFER_SIZE 128
#define CONFIG_MODEM_INFO_ADD_NETWORK 1
#define CONFIG_MODEM_INFO_ADD_SIM 1
#define CONFIG_MODEM_INFO_ADD_SIM_ICCID 1
#define CONFIG_MODEM_INFO_ADD_SIM_IMSI 1
#define CONFIG_MODEM_INFO_ADD_DEVICE 1
#define CONFIG_MODEM_INFO_ADD_BOARD 1
#define CONFIG_AT_CMD 1
#define CONFIG_AT_CMD_SYS_INIT 1
#define CONFIG_AT_CMD_INIT_PRIORITY 40
#define CONFIG_AT_CMD_THREAD_PRIO 10
#define CONFIG_AT_CMD_THREAD_STACK_SIZE 1024
#define CONFIG_AT_CMD_RESPONSE_MAX_LEN 2700
#define CONFIG_AT_CMD_RESPONSE_BUFFER_COUNT 2
#define CONFIG_AT_CMD_LOG_LEVEL_INF 1
#define CONFIG_AT_CMD_LOG_LEVEL 3
#define CONFIG_ENTROPY_CC310 1
#define CONFIG_NRF9160_GPS 1
#define CONFIG_NRF9160_GPS_DEV_NAME "NRF9160_GPS"
#define CONFIG_NRF9160_GPS_FIX_CHECK_INTERVAL 1
#define CONFIG_NRF9160_GPS_HANDLE_MODEM_CONFIGURATION 1
#define CONFIG_NRF9160_GPS_SET_MAGPIO 1
#define CONFIG_NRF9160_GPS_MAGPIO_STRING "AT%XMAGPIO=1,0,0,1,1,1574,1577"
#define CONFIG_NRF9160_GPS_SET_COEX0 1
#define CONFIG_NRF9160_GPS_COEX0_STRING "AT%XCOEX0=1,1,1570,1580"
#define CONFIG_NRF9160_GPS_NMEA_GGA 1
#define CONFIG_NRF9160_GPS_INIT_PRIO 90
#define CONFIG_NRF9160_GPS_THREAD_PRIORITY 10
#define CONFIG_NRF9160_GPS_THREAD_STACK_SIZE 2048
#define CONFIG_NRF9160_GPS_LOG_LEVEL_DBG 1
#define CONFIG_NRF9160_GPS_LOG_LEVEL 4
#define CONFIG_LTE_LINK_CONTROL 1
#define CONFIG_LTE_PSM_REQ_RPTAU "00000110"
#define CONFIG_LTE_PSM_REQ_RAT "00000000"
#define CONFIG_LTE_EDRX_REQ_ACTT_TYPE "4"
#define CONFIG_LTE_EDRX_REQ_VALUE "1000"
#define CONFIG_LTE_NETWORK_MODE_LTE_M_GPS 1
#define CONFIG_LTE_NETWORK_USE_FALLBACK 1
#define CONFIG_LTE_NETWORK_TIMEOUT 600
#define CONFIG_LTE_LINK_CONTROL_LOG_LEVEL_DBG 1
#define CONFIG_LTE_LINK_CONTROL_LOG_LEVEL 4
#define CONFIG_SENSOR 1
#define CONFIG_SENSOR_SIM 1
#define CONFIG_SENSOR_SIM_DEV_NAME "SENSOR_SIM"
#define CONFIG_SENSOR_SIM_DYNAMIC_VALUES 1
#define CONFIG_SENSOR_SIM_STATIC_VALUES 1
#define CONFIG_SENSOR_SIM_TRIGGER 1
#define CONFIG_SENSOR_SIM_TRIGGER_USE_TIMER 1
#define CONFIG_SENSOR_SIM_TRIGGER_TIMER_MSEC 1000
#define CONFIG_SENSOR_SIM_THREAD_PRIORITY 10
#define CONFIG_SENSOR_SIM_THREAD_STACK_SIZE 512
#define CONFIG_SENSOR_SIM_LOG_LEVEL_INF 1
#define CONFIG_SENSOR_SIM_LOG_LEVEL 3
#define CONFIG_CLOCK_CONTROL_NRF_K32SRC_XTAL 1
#define CONFIG_CLOCK_CONTROL_NRF_K32SRC_20PPM 1
#define CONFIG_CJSON_LIB 1
#define CONFIG_MCUBOOT_CMAKELISTS_DIR "$MCUBOOT_BASE/boot/zephyr/"
#define CONFIG_MCUBOOT_BUILD_STRATEGY_FROM_SOURCE 1
#define CONFIG_MCUBOOT_IMAGE_VERSION "0.0.0+0"
#define CONFIG_BOOT_SIGNATURE_KEY_FILE "root-rsa-2048.pem"
#define CONFIG_BSD_LIB 1
#define CONFIG_NRFXLIB_CRYPTO 1
#define CONFIG_NRF_OBERON 1
#define CONFIG_MBEDTLS_SHA256_SMALLER 1
#define CONFIG_MBEDTLS_TLS_VERSION_1_2 1
#define CONFIG_MBEDTLS_KEY_EXCHANGE_RSA_ENABLED 1
#define CONFIG_MBEDTLS_CIPHER_AES_ENABLED 1
#define CONFIG_MBEDTLS_AES_ROM_TABLES 1
#define CONFIG_MBEDTLS_CIPHER_DES_ENABLED 1
#define CONFIG_MBEDTLS_CIPHER_CBC_ENABLED 1
#define CONFIG_MBEDTLS_MAC_MD5_ENABLED 1
#define CONFIG_MBEDTLS_MAC_SHA1_ENABLED 1
#define CONFIG_MBEDTLS_MAC_SHA256_ENABLED 1
#define CONFIG_MBEDTLS_CTR_DRBG_ENABLED 1
#define CONFIG_HAS_NRFX 1
#define CONFIG_NRFX_NVMC 1
#define CONFIG_BOARD "nrf9160_pca10090"
#define CONFIG_FLASH_LOAD_SIZE 0x262144
#define CONFIG_FLASH_LOAD_OFFSET 0x40000
#define CONFIG_SOC "nRF9160_SICA"
#define CONFIG_SOC_SERIES "nrf91"
#define CONFIG_NUM_IRQS 65
#define CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC 32768
#define CONFIG_GPIO 1
#define CONFIG_ARCH_HAS_CUSTOM_BUSY_WAIT 1
#define CONFIG_ISR_STACK_SIZE 2048
#define CONFIG_CLOCK_CONTROL 1
#define CONFIG_NRF_RTC_TIMER 1
#define CONFIG_SYS_CLOCK_TICKS_PER_SEC 32768
#define CONFIG_SYS_POWER_MANAGEMENT 1
#define CONFIG_BUILD_OUTPUT_HEX 1
#define CONFIG_FLOAT 1
#define CONFIG_TEXT_SECTION_OFFSET 0x0
#define CONFIG_FLASH_SIZE 1024
#define CONFIG_FLASH_BASE_ADDRESS 0x0
#define CONFIG_SRAM_SIZE 128
#define CONFIG_SRAM_BASE_ADDRESS 0x20020000
#define CONFIG_SOC_GECKO_EMU 1
#define CONFIG_BOARD_NRF9160_PCA10090NS 1
#define CONFIG_SOC_SERIES_NRF91X 1
#define CONFIG_CPU_HAS_ARM_MPU 1
#define CONFIG_CPU_HAS_NRF_IDAU 1
#define CONFIG_SOC_FAMILY "nordic_nrf"
#define CONFIG_SOC_FAMILY_NRF 1
#define CONFIG_HAS_HW_NRF_CC310 1
#define CONFIG_HAS_HW_NRF_CLOCK 1
#define CONFIG_HAS_HW_NRF_DPPIC 1
#define CONFIG_HAS_HW_NRF_EGU0 1
#define CONFIG_HAS_HW_NRF_EGU1 1
#define CONFIG_HAS_HW_NRF_EGU2 1
#define CONFIG_HAS_HW_NRF_EGU3 1
#define CONFIG_HAS_HW_NRF_EGU4 1
#define CONFIG_HAS_HW_NRF_EGU5 1
#define CONFIG_HAS_HW_NRF_GPIO0 1
#define CONFIG_HAS_HW_NRF_GPIOTE 1
#define CONFIG_HAS_HW_NRF_I2S 1
#define CONFIG_HAS_HW_NRF_IPC 1
#define CONFIG_HAS_HW_NRF_PDM 1
#define CONFIG_HAS_HW_NRF_POWER 1
#define CONFIG_HAS_HW_NRF_PWM0 1
#define CONFIG_HAS_HW_NRF_PWM1 1
#define CONFIG_HAS_HW_NRF_PWM2 1
#define CONFIG_HAS_HW_NRF_PWM3 1
#define CONFIG_HAS_HW_NRF_RTC0 1
#define CONFIG_HAS_HW_NRF_RTC1 1
#define CONFIG_HAS_HW_NRF_SAADC 1
#define CONFIG_HAS_HW_NRF_SPIM0 1
#define CONFIG_HAS_HW_NRF_SPIM1 1
#define CONFIG_HAS_HW_NRF_SPIM2 1
#define CONFIG_HAS_HW_NRF_SPIM3 1
#define CONFIG_HAS_HW_NRF_SPIS0 1
#define CONFIG_HAS_HW_NRF_SPIS1 1
#define CONFIG_HAS_HW_NRF_SPIS2 1
#define CONFIG_HAS_HW_NRF_SPIS3 1
#define CONFIG_HAS_HW_NRF_SPU 1
#define CONFIG_HAS_HW_NRF_TIMER0 1
#define CONFIG_HAS_HW_NRF_TIMER1 1
#define CONFIG_HAS_HW_NRF_TIMER2 1
#define CONFIG_HAS_HW_NRF_TWIM0 1
#define CONFIG_HAS_HW_NRF_TWIM1 1
#define CONFIG_HAS_HW_NRF_TWIM2 1
#define CONFIG_HAS_HW_NRF_TWIM3 1
#define CONFIG_HAS_HW_NRF_TWIS0 1
#define CONFIG_HAS_HW_NRF_TWIS1 1
#define CONFIG_HAS_HW_NRF_TWIS2 1
#define CONFIG_HAS_HW_NRF_TWIS3 1
#define CONFIG_HAS_HW_NRF_UARTE0 1
#define CONFIG_HAS_HW_NRF_UARTE1 1
#define CONFIG_HAS_HW_NRF_UARTE2 1
#define CONFIG_HAS_HW_NRF_UARTE3 1
#define CONFIG_HAS_HW_NRF_WDT 1
#define CONFIG_NRF_ENABLE_ICACHE 1
#define CONFIG_SOC_NRF9160 1
#define CONFIG_SOC_NRF9160_SICA 1
#define CONFIG_SOC_LOG_LEVEL_INF 1
#define CONFIG_SOC_LOG_LEVEL 3
#define CONFIG_SOC_COMPATIBLE_NRF 1
#define CONFIG_CPU_CORTEX 1
#define CONFIG_CPU_CORTEX_M 1
#define CONFIG_ISA_THUMB2 1
#define CONFIG_DATA_ENDIANNESS_LITTLE 1
#define CONFIG_STACK_ALIGN_DOUBLE_WORD 1
#define CONFIG_FAULT_DUMP 2
#define CONFIG_BUILTIN_STACK_GUARD 1
#define CONFIG_ARM_STACK_PROTECTION 1
#define CONFIG_ARM_NONSECURE_FIRMWARE 1
#define CONFIG_ARM_FIRMWARE_USES_SECURE_ENTRY_FUNCS 1
#define CONFIG_FP_HARDABI 1
#define CONFIG_CPU_CORTEX_M33 1
#define CONFIG_CPU_CORTEX_M_HAS_SYSTICK 1
#define CONFIG_CPU_CORTEX_M_HAS_BASEPRI 1
#define CONFIG_CPU_CORTEX_M_HAS_VTOR 1
#define CONFIG_CPU_CORTEX_M_HAS_SPLIM 1
#define CONFIG_CPU_CORTEX_M_HAS_PROGRAMMABLE_FAULT_PRIOS 1
#define CONFIG_CPU_CORTEX_M_HAS_CMSE 1
#define CONFIG_ARMV7_M_ARMV8_M_MAINLINE 1
#define CONFIG_ARMV8_M_MAINLINE 1
#define CONFIG_ARMV8_M_SE 1
#define CONFIG_ARMV7_M_ARMV8_M_FP 1
#define CONFIG_ARMV8_M_DSP 1
#define CONFIG_LDREX_STREX_AVAILABLE 1
#define CONFIG_XIP 1
#define CONFIG_GEN_ISR_TABLES 1
#define CONFIG_PLATFORM_SPECIFIC_INIT 1
#define CONFIG_GEN_IRQ_VECTOR_TABLE 1
#define CONFIG_ARM_MPU 1
#define CONFIG_ARM_MPU_REGION_MIN_ALIGN_AND_SIZE 32
#define CONFIG_MPU_ALLOW_FLASH_WRITE 1
#define CONFIG_CUSTOM_SECTION_MIN_ALIGN_SIZE 32
#define CONFIG_ARM_TRUSTZONE_M 1
#define CONFIG_ARCH "arm"
#define CONFIG_ARM 1
#define CONFIG_ARCH_LOG_LEVEL_INF 1
#define CONFIG_ARCH_LOG_LEVEL 3
#define CONFIG_MPU_LOG_LEVEL_INF 1
#define CONFIG_MPU_LOG_LEVEL 3
#define CONFIG_TRUSTED_EXECUTION_NONSECURE 1
#define CONFIG_HW_STACK_PROTECTION 1
#define CONFIG_PRIVILEGED_STACK_SIZE 1024
#define CONFIG_PRIVILEGED_STACK_TEXT_AREA 256
#define CONFIG_KOBJECT_TEXT_AREA 256
#define CONFIG_GEN_SW_ISR_TABLE 1
#define CONFIG_ARCH_SW_ISR_TABLE_ALIGN 0
#define CONFIG_GEN_IRQ_START_VECTOR 0
#define CONFIG_ARCH_HAS_TRUSTED_EXECUTION 1
#define CONFIG_ARCH_HAS_STACK_PROTECTION 1
#define CONFIG_ARCH_HAS_USERSPACE 1
#define CONFIG_ARCH_HAS_EXECUTABLE_PAGE_BIT 1
#define CONFIG_ARCH_HAS_RAMFUNC_SUPPORT 1
#define CONFIG_ARCH_HAS_THREAD_ABORT 1
#define CONFIG_HAS_SYS_POWER_STATE_DEEP_SLEEP_1 1
#define CONFIG_CPU_HAS_TEE 1
#define CONFIG_CPU_HAS_FPU 1
#define CONFIG_CPU_HAS_MPU 1
#define CONFIG_MEMORY_PROTECTION 1
#define CONFIG_MPU_REQUIRES_NON_OVERLAPPING_REGIONS 1
#define CONFIG_FP_SHARING 1
#define CONFIG_KERNEL_LOG_LEVEL_INF 1
#define CONFIG_KERNEL_LOG_LEVEL 3
#define CONFIG_MULTITHREADING 1
#define CONFIG_NUM_COOP_PRIORITIES 16
#define CONFIG_NUM_PREEMPT_PRIORITIES 15
#define CONFIG_MAIN_THREAD_PRIORITY 7
#define CONFIG_COOP_ENABLED 1
#define CONFIG_PREEMPT_ENABLED 1
#define CONFIG_PRIORITY_CEILING 0
#define CONFIG_NUM_METAIRQ_PRIORITIES 0
#define CONFIG_MAIN_STACK_SIZE 8192
#define CONFIG_IDLE_STACK_SIZE 320
#define CONFIG_THREAD_STACK_INFO 1
#define CONFIG_ERRNO 1
#define CONFIG_SCHED_DUMB 1
#define CONFIG_WAITQ_DUMB 1
#define CONFIG_BOOT_BANNER 1
#define CONFIG_BOOT_DELAY 0
#define CONFIG_SYSTEM_WORKQUEUE_STACK_SIZE 2048
#define CONFIG_SYSTEM_WORKQUEUE_PRIORITY -1
#define CONFIG_OFFLOAD_WORKQUEUE_STACK_SIZE 1024
#define CONFIG_OFFLOAD_WORKQUEUE_PRIORITY -1
#define CONFIG_ATOMIC_OPERATIONS_BUILTIN 1
#define CONFIG_TIMESLICING 1
#define CONFIG_TIMESLICE_SIZE 0
#define CONFIG_TIMESLICE_PRIORITY 0
#define CONFIG_POLL 1
#define CONFIG_NUM_MBOX_ASYNC_MSGS 10
#define CONFIG_NUM_PIPE_ASYNC_MSGS 10
#define CONFIG_HEAP_MEM_POOL_SIZE 16384
#define CONFIG_HEAP_MEM_POOL_MIN_SIZE 64
#define CONFIG_ARCH_HAS_CUSTOM_SWAP_TO_MAIN 1
#define CONFIG_SWAP_NONATOMIC 1
#define CONFIG_SYS_CLOCK_EXISTS 1
#define CONFIG_KERNEL_INIT_PRIORITY_OBJECTS 30
#define CONFIG_KERNEL_INIT_PRIORITY_DEFAULT 40
#define CONFIG_KERNEL_INIT_PRIORITY_DEVICE 50
#define CONFIG_APPLICATION_INIT_PRIORITY 90
#define CONFIG_STACK_POINTER_RANDOM 0
#define CONFIG_MP_NUM_CPUS 1
#define CONFIG_TICKLESS_IDLE 1
#define CONFIG_TICKLESS_IDLE_THRESH 3
#define CONFIG_TICKLESS_KERNEL 1
#define CONFIG_SYS_PM_POLICY_RESIDENCY 1
#define CONFIG_SYS_PM_MIN_RESIDENCY_DEEP_SLEEP_1 60000
#define CONFIG_SYS_PM_LOG_LEVEL_INF 1
#define CONFIG_SYS_PM_LOG_LEVEL 3
#define CONFIG_HAS_DTS 1
#define CONFIG_HAS_DTS_GPIO 1
#define CONFIG_UART_CONSOLE_ON_DEV_NAME "UART_0"
#define CONFIG_CONSOLE 1
#define CONFIG_CONSOLE_INPUT_MAX_LINE_LEN 128
#define CONFIG_CONSOLE_HAS_DRIVER 1
#define CONFIG_CONSOLE_HANDLER 1
#define CONFIG_UART_CONSOLE 1
#define CONFIG_UART_CONSOLE_INIT_PRIORITY 60
#define CONFIG_UART_CONSOLE_DEBUG_SERVER_HOOKS 1
#define CONFIG_UART_CONSOLE_LOG_LEVEL_INF 1
#define CONFIG_UART_CONSOLE_LOG_LEVEL 3
#define CONFIG_SERIAL 1
#define CONFIG_SERIAL_HAS_DRIVER 1
#define CONFIG_SERIAL_SUPPORT_ASYNC 1
#define CONFIG_SERIAL_SUPPORT_INTERRUPT 1
#define CONFIG_UART_INTERRUPT_DRIVEN 1
#define CONFIG_UART_NRFX 1
#define CONFIG_UART_0_NRF_UARTE 1
#define CONFIG_UART_0_INTERRUPT_DRIVEN 1
#define CONFIG_UART_0_NRF_TX_BUFFER_SIZE 32
#define CONFIG_NRF_UARTE_PERIPHERAL 1
#define CONFIG_SYSTEM_CLOCK_DISABLE 1
#define CONFIG_SYSTEM_CLOCK_INIT_PRIORITY 0
#define CONFIG_TICKLESS_CAPABLE 1
#define CONFIG_ENTROPY_GENERATOR 1
#define CONFIG_ENTROPY_NRF_FORCE_ALT 1
#define CONFIG_ENTROPY_HAS_DRIVER 1
#define CONFIG_ENTROPY_NAME "ENTROPY_0"
#define CONFIG_GPIO_LOG_LEVEL_INF 1
#define CONFIG_GPIO_LOG_LEVEL 3
#define CONFIG_GPIO_NRFX 1
#define CONFIG_GPIO_NRF_INIT_PRIORITY 40
#define CONFIG_GPIO_NRF_P0 1
#define CONFIG_CLOCK_CONTROL_LOG_LEVEL_INF 1
#define CONFIG_CLOCK_CONTROL_LOG_LEVEL 3
#define CONFIG_CLOCK_CONTROL_NRF 1
#define CONFIG_IPM_LOG_LEVEL_INF 1
#define CONFIG_IPM_LOG_LEVEL 3
#define CONFIG_FLASH_HAS_DRIVER_ENABLED 1
#define CONFIG_FLASH_HAS_PAGE_LAYOUT 1
#define CONFIG_FLASH 1
#define CONFIG_FLASH_LOG_LEVEL_INF 1
#define CONFIG_FLASH_LOG_LEVEL 3
#define CONFIG_FLASH_PAGE_LAYOUT 1
#define CONFIG_SOC_FLASH_NRF 1
#define CONFIG_SENSOR_LOG_LEVEL_INF 1
#define CONFIG_SENSOR_LOG_LEVEL 3
#define CONFIG_SENSOR_INIT_PRIORITY 90
#define CONFIG_NEWLIB_LIBC 1
#define CONFIG_NEWLIB_LIBC_NANO 1
#define CONFIG_NEWLIB_LIBC_FLOAT_PRINTF 1
#define CONFIG_STDOUT_CONSOLE 1
#define CONFIG_JSON_LIBRARY 1
#define CONFIG_POSIX_MAX_FDS 4
#define CONFIG_MAX_TIMER_COUNT 5
#define CONFIG_UPDATEHUB_LOG_LEVEL_INF 1
#define CONFIG_UPDATEHUB_LOG_LEVEL 3
#define CONFIG_CONSOLE_SUBSYS 1
#define CONFIG_CONSOLE_GETCHAR 1
#define CONFIG_CONSOLE_GETCHAR_BUFSIZE 16
#define CONFIG_CONSOLE_PUTCHAR_BUFSIZE 16
#define CONFIG_PRINTK 1
#define CONFIG_EARLY_CONSOLE 1
#define CONFIG_ASSERT 1
#define CONFIG_ASSERT_LEVEL 2
#define CONFIG_HAS_SEGGER_RTT 1
#define CONFIG_LOG 1
#define CONFIG_LOG_DEFAULT_LEVEL 3
#define CONFIG_LOG_OVERRIDE_LEVEL 0
#define CONFIG_LOG_MAX_LEVEL 4
#define CONFIG_LOG_FUNC_NAME_PREFIX_DBG 1
#define CONFIG_LOG_IMMEDIATE 1
#define CONFIG_LOG_DOMAIN_ID 0
#define CONFIG_LOG_BACKEND_UART 1
#define CONFIG_LOG_BACKEND_SHOW_COLOR 1
#define CONFIG_LOG_BACKEND_FORMAT_TIMESTAMP 1
#define CONFIG_NET_BUF 1
#define CONFIG_NET_BUF_USER_DATA_SIZE 4
#define CONFIG_NET_BUF_LOG_LEVEL_INF 1
#define CONFIG_NET_BUF_LOG_LEVEL 3
#define CONFIG_NETWORKING 1
#define CONFIG_NET_INIT_PRIO 90
#define CONFIG_NET_IPV6 1
#define CONFIG_NET_IF_MAX_IPV6_COUNT 1
#define CONFIG_NET_IF_UNICAST_IPV6_ADDR_COUNT 2
#define CONFIG_NET_IF_MCAST_IPV6_ADDR_COUNT 3
#define CONFIG_NET_IF_IPV6_PREFIX_COUNT 2
#define CONFIG_NET_INITIAL_HOP_LIMIT 64
#define CONFIG_NET_IPV6_MAX_NEIGHBORS 8
#define CONFIG_NET_IPV6_MLD 1
#define CONFIG_NET_IPV6_NBR_CACHE 1
#define CONFIG_NET_IPV6_ND 1
#define CONFIG_NET_IPV6_DAD 1
#define CONFIG_NET_IPV6_RA_RDNSS 1
#define CONFIG_NET_IPV6_LOG_LEVEL 0
#define CONFIG_NET_ICMPV6_LOG_LEVEL 0
#define CONFIG_NET_IPV6_NBR_CACHE_LOG_LEVEL 0
#define CONFIG_NET_TC_TX_COUNT 1
#define CONFIG_NET_TC_RX_COUNT 1
#define CONFIG_NET_TC_MAPPING_STRICT 1
#define CONFIG_NET_TX_DEFAULT_PRIORITY 1
#define CONFIG_NET_RX_DEFAULT_PRIORITY 0
#define CONFIG_NET_IP_ADDR_CHECK 1
#define CONFIG_NET_MAX_ROUTERS 1
#define CONFIG_NET_ROUTE 1
#define CONFIG_NET_MAX_ROUTES 8
#define CONFIG_NET_MAX_NEXTHOPS 8
#define CONFIG_NET_UDP 1
#define CONFIG_NET_UDP_CHECKSUM 1
#define CONFIG_NET_UDP_LOG_LEVEL 0
#define CONFIG_NET_MAX_CONN 4
#define CONFIG_NET_MAX_CONTEXTS 6
#define CONFIG_NET_CONTEXT_SYNC_RECV 1
#define CONFIG_NET_CONTEXT_CHECK 1
#define CONFIG_NET_PKT_RX_COUNT 4
#define CONFIG_NET_PKT_TX_COUNT 4
#define CONFIG_NET_BUF_RX_COUNT 16
#define CONFIG_NET_BUF_TX_COUNT 16
#define CONFIG_NET_BUF_FIXED_DATA_SIZE 1
#define CONFIG_NET_BUF_DATA_SIZE 128
#define CONFIG_NET_DEFAULT_IF_FIRST 1
#define CONFIG_NET_TX_STACK_SIZE 1200
#define CONFIG_NET_RX_STACK_SIZE 1500
#define CONFIG_NET_PKT_LOG_LEVEL 0
#define CONFIG_NET_DEBUG_NET_PKT_EXTERNALS 0
#define CONFIG_NET_CORE_LOG_LEVEL 0
#define CONFIG_NET_IF_LOG_LEVEL 0
#define CONFIG_NET_TC_LOG_LEVEL 0
#define CONFIG_NET_UTILS_LOG_LEVEL 0
#define CONFIG_NET_CONTEXT_LOG_LEVEL 0
#define CONFIG_NET_CONN_LOG_LEVEL 0
#define CONFIG_NET_ROUTE_LOG_LEVEL 0
#define CONFIG_MQTT_LIB 1
#define CONFIG_MQTT_LOG_LEVEL 0
#define CONFIG_MQTT_LIB_TLS 1
#define CONFIG_NET_HTTP_LOG_LEVEL 0
#define CONFIG_NET_CONFIG_AUTO_INIT 1
#define CONFIG_NET_CONFIG_INIT_PRIO 95
#define CONFIG_NET_CONFIG_INIT_TIMEOUT 30
#define CONFIG_NET_CONFIG_LOG_LEVEL 0
#define CONFIG_NET_SOCKETS 1
#define CONFIG_NET_SOCKETS_POSIX_NAMES 1
#define CONFIG_NET_SOCKETS_POLL_MAX 3
#define CONFIG_NET_SOCKETS_CONNECT_TIMEOUT 3000
#define CONFIG_NET_SOCKETS_OFFLOAD 1
#define CONFIG_NET_SOCKETS_LOG_LEVEL 0
#define CONFIG_IMG_MANAGER 1
#define CONFIG_MCUBOOT_IMG_MANAGER 1
#define CONFIG_MCUBOOT_TRAILER_SWAP_TYPE 1
#define CONFIG_IMG_BLOCK_BUF_SIZE 512
#define CONFIG_IMG_MANAGER_LOG_LEVEL_INF 1
#define CONFIG_IMG_MANAGER_LOG_LEVEL 3
#define CONFIG_ENTROPY_DEVICE_RANDOM_GENERATOR 1
#define CONFIG_FLASH_MAP 1
#define CONFIG_TEST_EXTRA_STACKSIZE 0
#define CONFIG_TEST_ARM_CORTEX_M 1
#define CONFIG_HAS_CMSIS 1
#define CONFIG_LINKER_ORPHAN_SECTION_WARN 1
#define CONFIG_HAS_FLASH_LOAD_OFFSET 1
#define CONFIG_USE_CODE_PARTITION 1
#define CONFIG_KERNEL_ENTRY "__start"
#define CONFIG_LINKER_SORT_BY_ALIGNMENT 1
#define CONFIG_SIZE_OPTIMIZATIONS 1
#define CONFIG_COMPILER_OPT ""
#define CONFIG_KERNEL_BIN_NAME "zephyr"
#define CONFIG_OUTPUT_STAT 1
#define CONFIG_OUTPUT_DISASSEMBLY 1
#define CONFIG_OUTPUT_PRINT_MEMORY_USAGE 1
#define CONFIG_BUILD_OUTPUT_BIN 1
#define CONFIG_BOOTLOADER_MCUBOOT 1
#define CONFIG_REBOOT 1
#define CONFIG_COMPAT_INCLUDES 1
