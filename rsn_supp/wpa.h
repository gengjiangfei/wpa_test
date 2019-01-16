/*
 * wpa_supplicant - WPA definitions
 * Copyright (c) 2003-2015, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WPA_H
#define WPA_H

#include "common/defs.h"
#include "common/eapol_common.h"
#include "common/wpa_common.h"
#include "common/ieee802_11_defs.h"

struct wpa_sm;
struct eapol_sm;

struct wpa_sm_ctx
{
	void *ctx; /* pointer to arbitrary upper level context */ // wpa_s即wpa_supplicant全局结构体
	void *msg_ctx; /* upper level context for wpa_msg() calls */

	void (*set_state)(void *ctx, enum wpa_states state);
	enum wpa_states (*get_state)(void *ctx);
	void (*deauthenticate)(void * ctx, int reason_code); 
	int (*set_key)(void *ctx, enum wpa_alg alg,
		       const u8 *addr, int key_idx, int set_tx,
		       const u8 *seq, size_t seq_len,
		       const u8 *key, size_t key_len);
	void * (*get_network_ctx)(void *ctx);
	int (*get_bssid)(void *ctx, u8 *bssid);
	int (*ether_send)(void *ctx, const u8 *dest, u16 proto, const u8 *buf,size_t len);
//	int (*get_beacon_ie)(void *ctx);
	void (*cancel_auth_timeout)(void *ctx);
	u8 * (*alloc_eapol)(void *ctx, u8 type, const void *data, u16 data_len,
			    size_t *msg_len, void **data_pos);
	int (*add_pmkid)(void *ctx, void *network_ctx, const u8 *bssid,
			 const u8 *pmkid);
	int (*remove_pmkid)(void *ctx, void *network_ctx, const u8 *bssid,
			    const u8 *pmkid);
//	int (*mlme_setprotection)(void *ctx, const u8 *addr,
//				  int protection_type, int key_type);
	int (*mark_authenticated)(void *ctx, const u8 *target_ap);
	void (*set_rekey_offload)(void *ctx, const u8 *kek, size_t kek_len,
				  const u8 *kck, size_t kck_len,
				  const u8 *replay_ctr);
	int (*key_mgmt_set_pmk)(void *ctx, const u8 *pmk, size_t pmk_len);
};
#endif /* WPA_H */
