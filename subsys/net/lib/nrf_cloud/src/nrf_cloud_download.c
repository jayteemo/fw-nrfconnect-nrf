/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#if defined(CONFIG_FOTA_DOWNLOAD)
#include <net/fota_download.h>
#endif
#if defined(CONFIG_NRF_CLOUD_COAP)
#include "../coap/include/nrf_cloud_coap_transport.h"
#endif

#include "nrf_cloud_download.h"
LOG_MODULE_REGISTER(nrf_cloud_download, CONFIG_NRF_CLOUD_LOG_LEVEL);

static K_MUTEX_DEFINE(active_dl_mutex);
static struct nrf_cloud_download_data active_dl = { .type = NRF_CLOUD_DL_TYPE_NONE };

#if defined(CONFIG_NRF_CLOUD_COAP)
#define ACPT_IDX 0
#define PRXY_IDX 1
#define OPT_CNT  2
/* CoAP option array */
static struct coap_client_option cc_opts[OPT_CNT] = {0};
/* CoAP client to be used for file downloads */
static struct nrf_cloud_coap_client coap_client;
#endif

static int coap_dl_init(void)
{
#if defined(CONFIG_NRF_CLOUD_COAP)
	return nrf_cloud_coap_transport_init(&coap_client);
#else
	return 0;
#endif
}

static int coap_connect_and_auth(struct nrf_cloud_download_data *const dl)
{
#if defined(CONFIG_NRF_CLOUD_COAP)
	int ret = nrf_cloud_coap_transport_connect(&coap_client);

	if (ret) {
		LOG_ERR("CoAP connect failed, error; %d", ret);
		return -EIO;
	}

	ret = nrf_cloud_coap_transport_authenticate(&coap_client);
	if (ret) {
		LOG_ERR("CoAP authentication failed, error; %d", ret);
		return -EACCES;
	}
#endif
	return 0;
}

static int coap_dl_disconnect(void)
{
#if defined(CONFIG_NRF_CLOUD_COAP)
	return nrf_cloud_coap_transport_disconnect(&coap_client);
#else
	return 0;
#endif
}

static int dlc_start(struct nrf_cloud_download_data *const dl)
{
	int ret;
	const char *path = dl->path;

	if (IS_ENABLED(CONFIG_NRF_CLOUD_COAP)) {

		ret = coap_dl_init();
		if (ret) {
			/* ERROR TODO */
			return ret;
		}

		ret = coap_connect_and_auth(dl);
		if (ret) {
			/* ERROR TODO */
			return ret;
		}

		/* Set the download_client's coap_client */
		dl->dlc->coap.dlc_cc.cc = &coap_client.cc;

		/* Get the options for the proxy download */
		ret = nrf_cloud_coap_transport_proxy_dl_opts_get(&cc_opts[ACPT_IDX],
								 &cc_opts[PRXY_IDX],
								 dl->host, dl->path);
		if (ret) {
			LOG_ERR("Failed to set CoAP options, error: %d", ret);
			return ret;
		}

		/* Set the options in the download_client */
		dl->dlc->coap.dlc_cc.opts = cc_opts;
		dl->dlc->coap.dlc_cc.opt_cnt = OPT_CNT;

		/* Use nRF Cloud's proxy download resource */
		path = NRF_CLOUD_COAP_PROXY_RSC;
	}

	/* Start the download */
	return download_client_get(dl->dlc, dl->host, &dl->dl_cfg, path, 0);
}

static int dlc_disconnect(struct nrf_cloud_download_data *const dl)
{
	if (IS_ENABLED(CONFIG_NRF_CLOUD_COAP)) {
		return coap_dl_disconnect();
	}

	return download_client_disconnect(dl->dlc);
}

void nrf_cloud_download_end(void)
{
	k_mutex_lock(&active_dl_mutex, K_FOREVER);
	memset(&active_dl, 0, sizeof(active_dl));
	active_dl.type = NRF_CLOUD_DL_TYPE_NONE;
	k_mutex_unlock(&active_dl_mutex);
}

int nrf_cloud_download_start(struct nrf_cloud_download_data *const dl)
{
	if (!dl || !dl->path || (dl->type <= NRF_CLOUD_DL_TYPE_NONE) ||
	    (dl->type >= NRF_CLOUD_DL_TYPE_DL__LAST)) {
		return -EINVAL;
	}

	if (!IS_ENABLED(CONFIG_FOTA_DOWNLOAD) && (dl->type == NRF_CLOUD_DL_TYPE_FOTA)) {
		return -ENOTSUP;
	}

	int ret = 0;

	k_mutex_lock(&active_dl_mutex, K_FOREVER);

	/* FOTA has priority */
	if ((active_dl.type == NRF_CLOUD_DL_TYPE_FOTA) ||
	    ((active_dl.type != NRF_CLOUD_DL_TYPE_NONE) &&
	     (dl->type != NRF_CLOUD_DL_TYPE_FOTA))) {
		k_mutex_unlock(&active_dl_mutex);
		/* A download of equal or higher priority is already active. */
		return -EBUSY;
	}

	/* If a download is active, that means the incoming download request is a FOTA
	 * type, which has priority. Cancel the active download.
	 */
	if (active_dl.type == NRF_CLOUD_DL_TYPE_DL_CLIENT) {
		LOG_INF("Stopping active download, incoming FOTA update download has priority");
		ret = dlc_disconnect(&active_dl);

		if (ret) {
			LOG_ERR("download_client_disconnect() failed, error %d", ret);
		}
	}

	if (dl->type == NRF_CLOUD_DL_TYPE_FOTA) {
#if defined(CONFIG_FOTA_DOWNLOAD)
		ret = fota_download_start_with_image_type(dl->host, dl->path,
			dl->dl_cfg.sec_tag_count ? dl->dl_cfg.sec_tag_list[0] : -1,
			dl->dl_cfg.pdn_id, dl->dl_cfg.frag_size_override, dl->fota.expected_type);
#endif
	} else if (dl->type == NRF_CLOUD_DL_TYPE_DL_CLIENT) {
		ret = dlc_start(dl);
		if (ret) {
			(void)dlc_disconnect(dl);
		}
	} else {
		LOG_WRN("Unhandled download type: %d", dl->type);
		ret = -EFTYPE;
	}

	if (ret == 0) {
		active_dl = *dl;
	}
	k_mutex_unlock(&active_dl_mutex);

	return ret;
}
