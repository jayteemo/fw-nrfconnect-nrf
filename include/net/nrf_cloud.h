/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef NRF_CLOUD_H__
#define NRF_CLOUD_H__

#include <zephyr/kernel.h>
#include <zephyr/types.h>
#include <zephyr/net/mqtt.h>
#if defined(CONFIG_MODEM_INFO)
#include <modem/modem_info.h>
#endif
#include <cJSON.h>
#include <dfu/dfu_target_full_modem.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup nrf_cloud nRF Cloud
 * @{
 */

/** @defgroup nrf_cloud_mqtt_msg_ids MQTT message IDs for nRF Cloud.
 * @{
 */
#define NCT_MSG_ID_USE_NEXT_INCREMENT     0
#define NCT_MSG_ID_CC_SUB               100
#define NCT_MSG_ID_DC_SUB               101
#define NCT_MSG_ID_CG_SUB               102
#define NCT_MSG_ID_FOTA_SUB             103
#define NCT_MSG_ID_CC_UNSUB             150
#define NCT_MSG_ID_DC_UNSUB             151
#define NCT_MSG_ID_CG_UNSUB             152
#define NCT_MSG_ID_FOTA_UNSUB           153
#define NCT_MSG_ID_STATE_REQUEST        200
#define NCT_MSG_ID_FOTA_REQUEST         201
#define NCT_MSG_ID_FOTA_BLE_REQUEST     202
#define NCT_MSG_ID_STATE_REPORT         300
#define NCT_MSG_ID_PAIR_STATUS_REPORT   301
#define NCT_MSG_ID_FOTA_REPORT          302
#define NCT_MSG_ID_FOTA_BLE_REPORT      303
#define NCT_MSG_ID_INCREMENT_BEGIN     1000
#define NCT_MSG_ID_INCREMENT_END       9999
#define NCT_MSG_ID_USER_TAG_BEGIN      (NCT_MSG_ID_INCREMENT_END + 1)
#define NCT_MSG_ID_USER_TAG_END        0xFFFF /* MQTT message IDs are uint16_t */
/** @} */

/** Determines if an MQTT message ID is a user specified tag to be used for ACK matching */
#define IS_VALID_USER_TAG(tag) ((tag >= NCT_MSG_ID_USER_TAG_BEGIN) && \
				(tag <= NCT_MSG_ID_USER_TAG_END))
/** nRF Cloud's string identifier for persistent settings */
#define NRF_CLOUD_SETTINGS_NAME		"nrf_cloud"
#define NRF_CLOUD_SETTINGS_FOTA_KEY	"fota"
#define NRF_CLOUD_SETTINGS_FOTA_JOB	"job"
/** String used when defining a settings handler for FOTA */
#define NRF_CLOUD_SETTINGS_FULL_FOTA		NRF_CLOUD_SETTINGS_NAME \
						"/" \
						NRF_CLOUD_SETTINGS_FOTA_KEY
/** String used when saving FOTA job info to settings */
#define NRF_CLOUD_SETTINGS_FULL_FOTA_JOB	NRF_CLOUD_SETTINGS_FULL_FOTA \
						"/" \
						NRF_CLOUD_SETTINGS_FOTA_JOB

/** Current FOTA version number */
#define NRF_CLOUD_FOTA_VER              2
/** Current FOTA version string used in device shadow */
#define NRF_CLOUD_FOTA_VER_STR "fota_v" STRINGIFY(NRF_CLOUD_FOTA_VER)
/** Max length of nRF Cloud's stage/environment name */
#define NRF_CLOUD_STAGE_ID_MAX_LEN      8
/** Max length of a tenant ID on nRF Cloud */
#define NRF_CLOUD_TENANT_ID_MAX_LEN     64
/** Max length of a device's MQTT client ID (device ID) on nRF Cloud*/
#define NRF_CLOUD_CLIENT_ID_MAX_LEN     64
/** Maximum valid duration for JWTs generated by @ref nrf_cloud_jwt_generate */
#define NRF_CLOUD_JWT_VALID_TIME_S_MAX	(7 * 24 * 60 * 60)
/** Default valid duration for JWTs generated by @ref nrf_cloud_jwt_generate */
#define NRF_CLOUD_JWT_VALID_TIME_S_DEF	(10 * 60)

/** @brief Asynchronous nRF Cloud events notified by the module. */
enum nrf_cloud_evt_type {
	/** The transport to the nRF Cloud is established. */
	NRF_CLOUD_EVT_TRANSPORT_CONNECTED = 0x1,
	/** In the process of connecting to nRF Cloud. */
	NRF_CLOUD_EVT_TRANSPORT_CONNECTING,
	/** There was a request from nRF Cloud to associate the device
	 * with a user on the nRF Cloud.
	 */
	NRF_CLOUD_EVT_USER_ASSOCIATION_REQUEST,
	/** The device is successfully associated with a user. */
	NRF_CLOUD_EVT_USER_ASSOCIATED,
	/** The device can now start sending sensor data to the cloud. */
	NRF_CLOUD_EVT_READY,
	/** The device received data from the cloud. */
	NRF_CLOUD_EVT_RX_DATA,
	/** The device has received a ping response from the cloud. */
	NRF_CLOUD_EVT_PINGRESP,
	/** The data sent to the cloud was acknowledged. */
	NRF_CLOUD_EVT_SENSOR_DATA_ACK,
	/** The transport was disconnected. */
	NRF_CLOUD_EVT_TRANSPORT_DISCONNECTED,
	/** A FOTA update has started. */
	NRF_CLOUD_EVT_FOTA_START,
	/** The device should be restarted to apply a firmware upgrade */
	NRF_CLOUD_EVT_FOTA_DONE,
	/** An error occurred during the FOTA update. */
	NRF_CLOUD_EVT_FOTA_ERROR,
	/** There was an error communicating with the cloud. */
	NRF_CLOUD_EVT_ERROR = 0xFF
};

/**@ nRF Cloud disconnect status. */
enum nrf_cloud_disconnect_status {
	NRF_CLOUD_DISCONNECT_USER_REQUEST,
	NRF_CLOUD_DISCONNECT_CLOSED_BY_REMOTE,
	NRF_CLOUD_DISCONNECT_INVALID_REQUEST,
	NRF_CLOUD_DISCONNECT_MISC,
	NRF_CLOUD_DISCONNECT_COUNT
};

/**@ nRF Cloud connect result. */
enum nrf_cloud_connect_result {
	NRF_CLOUD_CONNECT_RES_SUCCESS = 0,
	NRF_CLOUD_CONNECT_RES_ERR_NOT_INITD = -1,
	NRF_CLOUD_CONNECT_RES_ERR_INVALID_PARAM = -2,
	NRF_CLOUD_CONNECT_RES_ERR_NETWORK = -3,
	NRF_CLOUD_CONNECT_RES_ERR_BACKEND = -4,
	NRF_CLOUD_CONNECT_RES_ERR_MISC = -5,
	NRF_CLOUD_CONNECT_RES_ERR_NO_MEM = -6,
	/** Invalid private key */
	NRF_CLOUD_CONNECT_RES_ERR_PRV_KEY = -7,
	/** Invalid CA or client cert */
	NRF_CLOUD_CONNECT_RES_ERR_CERT = -8,
	/** Other cert issue */
	NRF_CLOUD_CONNECT_RES_ERR_CERT_MISC = -9,
	/** Timeout, SIM card may be out of data */
	NRF_CLOUD_CONNECT_RES_ERR_TIMEOUT_NO_DATA = -10,
	NRF_CLOUD_CONNECT_RES_ERR_ALREADY_CONNECTED = -11,
};

/**@ nRF Cloud error codes. */
enum nrf_cloud_error {
	NRF_CLOUD_ERROR_UNKNOWN			= -1,
	NRF_CLOUD_ERROR_NONE			= 0,
	/** nRF Cloud API error codes */
	NRF_CLOUD_ERROR_BAD_REQUEST		= 40000,
	NRF_CLOUD_ERROR_INVALID_CERT		= 40001,
	NRF_CLOUD_ERROR_DISSOCIATE		= 40002,
	NRF_CLOUD_ERROR_ACCESS_DENIED		= 40100,
	NRF_CLOUD_ERROR_DEV_ID_IN_USE		= 40101,
	NRF_CLOUD_ERROR_INVALID_OWNER_CODE	= 40102,
	NRF_CLOUD_ERROR_DEV_NOT_ASSOCIATED	= 40103,
	NRF_CLOUD_ERROR_DATA_NOT_FOUND		= 40410,
	NRF_CLOUD_ERROR_NRF_DEV_NOT_FOUND	= 40411,
	NRF_CLOUD_ERROR_NO_DEV_NOT_PROV		= 40412,
	NRF_CLOUD_ERROR_NO_DEV_DISSOCIATE	= 40413,
	NRF_CLOUD_ERROR_NO_DEV_DELETE		= 40414,
	/** Item was not found. No error occured, the requested item simply does not exist */
	NRF_CLOUD_ERROR_NOT_FOUND_NO_ERROR	= 40499,
	NRF_CLOUD_ERROR_BAD_RANGE		= 41600,
	NRF_CLOUD_ERROR_VALIDATION		= 42200,
	NRF_CLOUD_ERROR_INTERNAL_SERVER		= 50010,
};

/** @brief Sensor types supported by the nRF Cloud. */
enum nrf_cloud_sensor {
	/** The GPS sensor on the device. */
	NRF_CLOUD_SENSOR_GPS,
	/** The FLIP movement sensor on the device. */
	NRF_CLOUD_SENSOR_FLIP,
	/** The Button press sensor on the device. */
	NRF_CLOUD_SENSOR_BUTTON,
	/** The TEMP sensor on the device. */
	NRF_CLOUD_SENSOR_TEMP,
	/** The Humidity sensor on the device. */
	NRF_CLOUD_SENSOR_HUMID,
	/** The Air Pressure sensor on the device. */
	NRF_CLOUD_SENSOR_AIR_PRESS,
	/** The Air Quality sensor on the device. */
	NRF_CLOUD_SENSOR_AIR_QUAL,
	/** The RSPR data obtained from the modem. */
	NRF_CLOUD_LTE_LINK_RSRP,
	/** The descriptive DEVICE data indicating its status. */
	NRF_CLOUD_DEVICE_INFO,
	/** The light sensor on the device. */
	NRF_CLOUD_SENSOR_LIGHT,
};

/** @brief Topic types supported by nRF Cloud. */
enum nrf_cloud_topic_type {
	/** Endpoint used to update the cloud-side device shadow state . */
	NRF_CLOUD_TOPIC_STATE = 0x1,
	/** Endpoint used to directly message the nRF Cloud Web UI. */
	NRF_CLOUD_TOPIC_MESSAGE,
	/** Endpoint used to publish bulk messages to nRF Cloud. Bulk messages combine multiple
	 *  messages into a single message that will be unwrapped and re-published to the
	 *  message topic in the nRF Cloud backend.
	 */
	NRF_CLOUD_TOPIC_BULK
};

/**@brief FOTA status reported to nRF Cloud. */
enum nrf_cloud_fota_status {
	NRF_CLOUD_FOTA_QUEUED = 0,
	NRF_CLOUD_FOTA_IN_PROGRESS = 1,
	NRF_CLOUD_FOTA_FAILED = 2,
	NRF_CLOUD_FOTA_SUCCEEDED = 3,
	NRF_CLOUD_FOTA_TIMED_OUT = 4,
	NRF_CLOUD_FOTA_CANCELED = 5,
	NRF_CLOUD_FOTA_REJECTED = 6,
	NRF_CLOUD_FOTA_DOWNLOADING = 7,
};

/**@brief FOTA update type. */
enum nrf_cloud_fota_type {
	NRF_CLOUD_FOTA_TYPE__FIRST = 0,

	/** Application update. */
	NRF_CLOUD_FOTA_APPLICATION = NRF_CLOUD_FOTA_TYPE__FIRST,
	/** Delta modem update */
	NRF_CLOUD_FOTA_MODEM_DELTA = 1,
	/** Bootloader update. */
	NRF_CLOUD_FOTA_BOOTLOADER = 2,

	/* Types not handled by this library:
	 * NRF_CLOUD_FOTA_BLE_BOOT = 3,
	 * NRF_CLOUD_FOTA_BLE_SOFTDEVICE = 4,
	 */

	/** Full modem update */
	NRF_CLOUD_FOTA_MODEM_FULL = 5,

	NRF_CLOUD_FOTA_TYPE__INVALID
};

/** Size of nRF Cloud FOTA job ID; version 4 UUID: 32 bytes, 4 hyphens, NULL */
#define NRF_CLOUD_FOTA_JOB_ID_SIZE (32 + 4 + 1)

/**@brief Common FOTA job info */
struct nrf_cloud_fota_job_info {
	enum nrf_cloud_fota_type type;
	/** Null-terminated FOTA job identifier */
	char *id;
	char *host;
	char *path;
	int file_size;
};

/** Validity of an in-progress/installed FOTA update */
enum nrf_cloud_fota_validate_status {
	NRF_CLOUD_FOTA_VALIDATE_NONE = 0,
	NRF_CLOUD_FOTA_VALIDATE_PENDING,
	NRF_CLOUD_FOTA_VALIDATE_PASS,
	NRF_CLOUD_FOTA_VALIDATE_FAIL,
	NRF_CLOUD_FOTA_VALIDATE_UNKNOWN,
	NRF_CLOUD_FOTA_VALIDATE_DONE
};

/** Status flags for tracking the update process of the b1 bootloader (MCUBOOT) */
enum nrf_cloud_fota_bootloader_status_flags {
	NRF_CLOUD_FOTA_BL_STATUS_CLEAR		= 0,
	NRF_CLOUD_FOTA_BL_STATUS_S0_FLAG_SET	= (1 << 0),
	NRF_CLOUD_FOTA_BL_STATUS_S0_WAS_ACTIVE	= (1 << 1),
	NRF_CLOUD_FOTA_BL_STATUS_REBOOTED	= (1 << 2),
};

/** @brief FOTA job info provided to the settings module to track FOTA job status. */
struct nrf_cloud_settings_fota_job {
	enum nrf_cloud_fota_validate_status validate;
	enum nrf_cloud_fota_type type;
	char id[NRF_CLOUD_FOTA_JOB_ID_SIZE];
	enum nrf_cloud_fota_bootloader_status_flags bl_flags;
};

/**@brief Generic encapsulation for any data that is sent to the cloud. */
struct nrf_cloud_data {
	/** Length of the data. */
	uint32_t len;
	/** Pointer to the data. */
	const void *ptr;
};

/**@brief MQTT topic. */
struct nrf_cloud_topic {
	/** Length of the topic. */
	uint32_t len;
	/** Pointer to the topic. */
	const void *ptr;
};

/**@brief Sensors that are supported by the device. */
struct nrf_cloud_sensor_list {
	/** Size of the list. */
	uint8_t size;
	/** Supported sensor types. */
	const enum nrf_cloud_sensor *ptr;
};

/**@brief Connection parameters. */
struct nrf_cloud_connect_param {
	/** Supported sensor types. May be NULL. */
	const struct nrf_cloud_sensor_list *sensor;
};

/**@brief Sensor data transmission parameters. */
struct nrf_cloud_sensor_data {
	/** The sensor that is the source of the data. */
	enum nrf_cloud_sensor type;
	/** Sensor data to be transmitted. */
	struct nrf_cloud_data data;
	/** Unique tag to identify the sent data. Can be used to match
	 * acknowledgment on the NRF_CLOUD_EVT_SENSOR_DATA_ACK event.
	 * Valid range: NCT_MSG_ID_USER_TAG_BEGIN to NCT_MSG_ID_USER_TAG_END.
	 * Any other value will suppress the NRF_CLOUD_EVT_SENSOR_DATA_ACK event.
	 */
	uint16_t tag;
};

/**@brief Asynchronous events received from the module. */
struct nrf_cloud_evt {
	/** The event that occurred. */
	enum nrf_cloud_evt_type type;
	/** Any status associated with the event. */
	uint32_t status;
	/** Received data. */
	struct nrf_cloud_data data;
	/** Topic on which data was received. */
	struct nrf_cloud_topic topic;
};

/**@brief Structure used to send pre-encoded data to nRF Cloud. */
struct nrf_cloud_tx_data {
	/** Data that is to be published. */
	struct nrf_cloud_data data;
	/** Endpoint topic type published to. */
	enum nrf_cloud_topic_type topic_type;
	/** Quality of Service of the message. */
	enum mqtt_qos qos;
	/** Message ID */
	uint32_t id;
};

/**@brief Controls which values are added to the FOTA array in the "serviceInfo" shadow section */
struct nrf_cloud_svc_info_fota {
	uint8_t bootloader:1;
	uint8_t modem:1;
	uint8_t application:1;
	uint8_t modem_full:1;

	uint8_t _rsvd:4;
};

/**@brief Controls which values are added to the UI array in the "serviceInfo" shadow section */
struct nrf_cloud_svc_info_ui {
	/** Items with UI support on nRF Cloud */
	uint8_t temperature:1;
	uint8_t gps:1; /* Location (map) */
	uint8_t flip:1; /* Orientation */
	uint8_t humidity:1;
	uint8_t air_pressure:1;
	uint8_t rsrp:1;

	/** Items without UI support on nRF Cloud */
	uint8_t air_quality:1;
	uint8_t light_sensor:1;
	uint8_t button:1;

	uint8_t _rsvd:7;
};

/**@brief How the info sections are handled when encoding shadow data */
enum nrf_cloud_shadow_info {
	/** Data will not be modified */
	NRF_CLOUD_INFO_NO_CHANGE = 0,
	/** Data will be set/updated */
	NRF_CLOUD_INFO_SET = 1,
	/** Data section will be cleared */
	NRF_CLOUD_INFO_CLEAR = 2,
};

/**@brief Modem info data and which sections should be encoded */
struct nrf_cloud_modem_info {
	enum nrf_cloud_shadow_info device;
	enum nrf_cloud_shadow_info network;
	enum nrf_cloud_shadow_info sim;

#if defined(CONFIG_MODEM_INFO)
	/** Pointer to a populated @ref modem_param_info struct.
	 * If NULL, modem data will be fetched.
	 */
	const struct modem_param_info *mpi;
#endif

};

/**@brief Structure to specify which components are added to the encoded service info object */
struct nrf_cloud_svc_info {
	/** Specify FOTA components to enable, set to NULL to remove the FOTA entry */
	struct nrf_cloud_svc_info_fota *fota;
	/** Specify UI components to enable, set to NULL to remove the UI entry */
	struct nrf_cloud_svc_info_ui *ui;
};

/**@brief Structure to specify which components are added to the encoded device status object */
struct nrf_cloud_device_status {
	/** Specify which modem info components to include, set to NULL to skip */
	struct nrf_cloud_modem_info *modem;
	/** Specify which service info components to include, set to NULL to skip */
	struct nrf_cloud_svc_info *svc;
};

#ifdef CONFIG_NRF_CLOUD_GATEWAY
/**@brief Structure to hold message received from nRF Cloud. */
struct nrf_cloud_gw_data {
	struct nrf_cloud_data data;
	uint16_t id;
};
#endif

/**
 * @brief  Event handler registered with the module to handle asynchronous
 * events from the module.
 *
 * @param[in]  evt The event and any associated parameters.
 */
typedef void (*nrf_cloud_event_handler_t)(const struct nrf_cloud_evt *evt);

/**@brief Initialization parameters for the module. */
struct nrf_cloud_init_param {
	/** Event handler that is registered with the module. */
	nrf_cloud_event_handler_t event_handler;
	/** NULL-terminated MQTT client ID string.
	 * Must not exceed NRF_CLOUD_CLIENT_ID_MAX_LEN.
	 * Must be set if NRF_CLOUD_CLIENT_ID_SRC_RUNTIME
	 * is enabled; otherwise, NULL.
	 */
	char *client_id;
	/** Flash device information required for full modem FOTA updates.
	 * Only used if CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE is enabled.
	*/
	struct dfu_target_fmfu_fdev *fmfu_dev_inf;
};

/**
 * @brief Initialize the module.
 *
 * @note This API must be called prior to using nRF Cloud
 *       and it must return successfully.
 *
 * @param[in] param Initialization parameters.
 *
 * @retval 0       If successful.
 * @retval -EACCES Already initialized or @ref nrf_cloud_uninit is in progress.
 *                 Otherwise, a (negative) error code is returned.
 */
int nrf_cloud_init(const struct nrf_cloud_init_param *param);

/**
 * @brief Uninitialize nRF Cloud; disconnects cloud connection
 *  and cleans up allocated memory.
 *
 * @note If nRF Cloud FOTA is enabled and a FOTA job is active
 *  uninit will not be performed.
 *
 * @retval 0      If successful.
 * @retval -EBUSY If a FOTA job is in progress.
 *                Otherwise, a (negative) error code is returned.
 */
int nrf_cloud_uninit(void);

/**
 * @brief Connect to the cloud.
 *
 * In any stage of connecting to the cloud, an @ref NRF_CLOUD_EVT_ERROR
 * might be received.
 * If it is received before @ref NRF_CLOUD_EVT_TRANSPORT_CONNECTED,
 * the application may repeat the call to @ref nrf_cloud_connect to try again.
 *
 * @param[in] param Parameters to be used for the connection.
 *
 * @retval Connect result defined by enum nrf_cloud_connect_result.
 */
int nrf_cloud_connect(const struct nrf_cloud_connect_param *param);

/**
 * @brief Send sensor data reliably.
 *
 * This API should only be called after receiving an
 * @ref NRF_CLOUD_EVT_READY event.
 * If the API succeeds, you can expect the
 * @ref NRF_CLOUD_EVT_SENSOR_DATA_ACK event for data sent with
 * a valid tag value.
 *
 * @param[in] param Sensor data; the data pointed to by param->data.ptr
 *                  must be a string.
 *
 * @retval 0       If successful.
 * @retval -EACCES Cloud connection is not established; wait for @ref NRF_CLOUD_EVT_READY.
 *                 Otherwise, a (negative) error code is returned.
 */
int nrf_cloud_sensor_data_send(const struct nrf_cloud_sensor_data *param);

/**
 * @brief Update the device shadow with sensor data.
 *
 * @param[in] param Sensor data; the data pointed to by param->data.ptr must be a
 *                  valid JSON string.
 *
 * @retval 0       If successful.
 * @retval -EACCES Cloud connection is not established; wait for @ref NRF_CLOUD_EVT_READY.
 *                 Otherwise, a (negative) error code is returned.
 */
int nrf_cloud_shadow_update(const struct nrf_cloud_sensor_data *param);

/**
 * @brief Update the device status in the shadow.
 *
 * @param[in] dev_status Device status to be encoded.
 *
 * @retval 0       If successful.
 * @retval -EACCES Cloud connection is not established; wait for @ref NRF_CLOUD_EVT_READY.
 *                 Otherwise, a (negative) error code is returned.
 */
int nrf_cloud_shadow_device_status_update(const struct nrf_cloud_device_status * const dev_status);

/**
 * @brief Stream sensor data. Uses lowest QoS; no acknowledgment,
 *
 * This API should only be called after receiving an
 * @ref NRF_CLOUD_EVT_READY event.
 *
 * @param[in] param Sensor data; tag value is ignored.
 *
 * @retval 0       If successful.
 * @retval -EACCES Cloud connection is not established; wait for @ref NRF_CLOUD_EVT_READY.
 *                 Otherwise, a (negative) error code is returned.
 */
int nrf_cloud_sensor_data_stream(const struct nrf_cloud_sensor_data *param);

/**
 * @brief Send data to nRF Cloud.
 *
 * This API is used to send pre-encoded data to nRF Cloud.
 *
 * @param[in] msg Pointer to a structure containting data and topic
 *                information.
 *
 * @retval 0       If successful.
 * @retval -EACCES Cloud connection is not established; wait for @ref NRF_CLOUD_EVT_READY.
 *                 Otherwise, a (negative) error code is returned.
 */
int nrf_cloud_send(const struct nrf_cloud_tx_data *msg);

/**
 * @brief Disconnect from the cloud.
 *
 * This API may be called any time after receiving the
 * @ref NRF_CLOUD_EVT_TRANSPORT_CONNECTED event.
 * If the API succeeds, you can expect the
 * @ref NRF_CLOUD_EVT_TRANSPORT_DISCONNECTED event.
 *
 * @retval 0       If successful.
 * @retval -EACCES Cloud connection is not established; wait for
 *                 @ref NRF_CLOUD_EVT_TRANSPORT_CONNECTED.
 *                 Otherwise, a (negative) error code is returned.
 */
int nrf_cloud_disconnect(void);

/**
 * @brief Function that must be called periodically to keep the module
 * functional.
 *
 * @retval 0 If successful.
 *           Otherwise, a (negative) error code is returned.
 */
int nrf_cloud_process(void);

/**
 * @brief The application has handled reinit after a modem FOTA update and the
 *        LTE link has been reestablished.
 *        This function must be called in order to complete the modem update.
 *        Depends on CONFIG_NRF_CLOUD_FOTA.
 *
 * @param[in] fota_success true if modem update was successful, false otherwise.
 *
 * @retval 0 If successful.
 *           Otherwise, a (negative) error code is returned.
 */
int nrf_cloud_modem_fota_completed(const bool fota_success);

/**
 * @brief Add service info into the provided cJSON object.
 *
 * @param[in]     svc_inf     Service info to add.
 * @param[in,out] svc_inf_obj cJSON object to which service info will be added.
 *
 * @retval 0 If successful.
 *           Otherwise, a (negative) error code is returned.
 */
int nrf_cloud_service_info_json_encode(const struct nrf_cloud_svc_info * const svc_inf,
				       cJSON * const svc_inf_obj);

/**
 * @brief Add modem info into the provided cJSON object.
 *
 * @note To add modem info, CONFIG_MODEM_INFO must be enabled.
 *
 * @param[in]     mod_inf     Modem info to add.
 * @param[in,out] mod_inf_obj cJSON object to which modem info will be added.
 *
 * @retval 0 If successful.
 *           Otherwise, a (negative) error code is returned.
 */
int nrf_cloud_modem_info_json_encode(const struct nrf_cloud_modem_info * const mod_inf,
				     cJSON * const mod_inf_obj);

/**
 * @brief Function to retrieve the current device ID.
 *
 * @param[in,out] id_buf Buffer to receive the device ID.
 * @param[in] id_len     Size of buffer (NRF_CLOUD_CLIENT_ID_MAX_LEN).
 *
 * @retval 0 If successful.
 *           Otherwise, a (negative) error code is returned.
 */
int nrf_cloud_client_id_get(char *id_buf, size_t id_len);

/**
 * @brief Function to retrieve the current customer tenant ID.
 *
 * @param[in,out] id_buf Buffer to receive the tenant ID.
 * @param[in] id_len     Size of buffer (NRF_CLOUD_TENANT_ID_MAX_LEN).
 *
 * @retval 0 If successful.
 *           Otherwise, a (negative) error code is returned.
 */
int nrf_cloud_tenant_id_get(char *id_buf, size_t id_len);

/**
 * @brief Function to generate a JWT to be used with nRF Cloud's REST API.
 *        This library's configured values for client id and sec tag (NRF_CLOUD_SEC_TAG)
 *        will be used for generating the JWT.
 *
 * @param[in] time_valid_s How long (seconds) the JWT will be valid. Maximum
 *                         duration specified by @ref NRF_CLOUD_JWT_VALID_TIME_S_MAX.
 *                         If zero, NRF_CLOUD_JWT_VALID_TIME_S_DEF will be used.
 * @param[in,out] jwt_buf Buffer to hold the JWT.
 * @param[in] jwt_buf_sz  Size of the buffer (recommended size >= 600 bytes).
 *
 * @retval 0      JWT generated successfully.
 * @retval -ETIME Modem does not have valid date/time, JWT not generated.
 * @return A negative value indicates an error.
 */
int nrf_cloud_jwt_generate(uint32_t time_valid_s, char * const jwt_buf, size_t jwt_buf_sz);

/**
 * @brief Function to process/validate a pending FOTA update job. Typically the job
 *        information is read from non-volatile storage on startup. This function
 *        is intended to be used by custom REST-based FOTA implementations.
 *        It is called internally if CONFIG_NRF_CLOUD_FOTA is enabled.
 *
 * @param[in] job FOTA job state information.
 * @param[out] reboot_required A reboot is needed to complete a FOTA update.
 *
 * @retval 0       A Pending FOTA job has been processed.
 * @retval -ENODEV No pending/unvalidated FOTA job exists.
 * @retval -ENOENT Error; unknown FOTA job type.
 * @retval -ESRCH Error; not configured for FOTA job type.
 */
int nrf_cloud_pending_fota_job_process(struct nrf_cloud_settings_fota_job * const job,
				       bool * const reboot_required);

/**
 * @brief Function to set the active bootloader (B1) slot flag which is needed
 *        to validate a bootloader FOTA update. For proper functionality,
 *        CONFIG_FOTA_DOWNLOAD must be enabled.
 *
 * @param[in,out] job FOTA job state information.
 *
 * @retval 0 Flag set successfully or not a bootloader FOTA update.
 * @return A negative value indicates an error.
 */
int nrf_cloud_bootloader_fota_slot_set(struct nrf_cloud_settings_fota_job * const job);

/**
 * @brief Function to check for a JSON error message in data received from nRF Cloud via MQTT.
 *
 * @param[in] buf Data received from nRF Cloud.
 * @param[in] app_id appId value to check for.
 *                   Set to NULL to skip appID check.
 * @param[in] msg_type messageType value to check for.
 *                     Set to NULL to skip messageType check.
 * @param[out] err Error code found in message.
 *
 * @retval 0 Error code found (and matched app_id and msg_type if provided).
 * @retval -ENOENT Error code found, but did not match specified app_id and msg_type.
 * @retval -ENOMSG No error code found.
 * @retval -EBADMSG Invalid error code data format.
 * @retval -ENODATA JSON data was not found.
 * @return A negative value indicates an error.
 */
int nrf_cloud_handle_error_message(const char *const buf,
				   const char *const app_id,
				   const char *const msg_type,
				   enum nrf_cloud_error *const err);

/**
 * @brief Function to validate a pending FOTA installation before initializing this library.
 *        This function enables the application to control the reboot/reinit process during FOTA
 *        updates. If this function is not called directly by the application, it will
 *        be called internally when @ref nrf_cloud_init is executed.
 *        Depends on CONFIG_NRF_CLOUD_FOTA.
 *
 * @param[out] fota_type_out FOTA type of pending job.
 *                           NRF_CLOUD_FOTA_TYPE__INVALID if no pending job.
 *                           Can be NULL.
 *
 * @retval 0 Pending FOTA job processed.
 * @retval 1 Pending FOTA job processed and requires the application to perform a reboot or,
 *           for modem FOTA types, reinitialization of the modem library.
 * @retval -ENODEV No pending/unvalidated FOTA job exists.
 * @retval -EIO Error; failed to load FOTA job info from settings module.
 * @retval -ENOENT Error; unknown FOTA job type.
 */
int nrf_cloud_fota_pending_job_validate(enum nrf_cloud_fota_type * const fota_type_out);

/**
 * @brief Function to set the flash device used for full modem FOTA updates.
 *
 * @param[in] fmfu_dev_inf Flash device information.
 *
 * @retval 0 Flash device was successfully set.
 * @return A negative value indicates an error.
 */
int nrf_cloud_fota_fmfu_dev_set(const struct dfu_target_fmfu_fdev *const fmfu_dev_inf);

/**
 * @brief Function to install a full modem update from flash. If successful,
 *        reboot the device or reinit the modem to complete the update.
 *        This function is intended to be used by custom REST-based FOTA implementations.
 *        If CONFIG_NRF_CLOUD_FOTA is enabled, call @ref nrf_cloud_fota_pending_job_validate
 *        to install a downloaded NRF_CLOUD_FOTA_MODEM_FULL update after the
 *        @ref NRF_CLOUD_EVT_FOTA_DONE event is received.
 *        Depends on CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE.
 *
 * @retval 0 Modem update installed successfully.
 * @return A negative value indicates an error. Modem update not installed.
 */
int nrf_cloud_fota_fmfu_apply(void);

/**
 * @brief Function to determine if FOTA type is modem related.
 *
 * @return true if FOTA is modem type, otherwise false.
 */
bool nrf_cloud_fota_is_type_modem(const enum nrf_cloud_fota_type type);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* NRF_CLOUD_H__ */
