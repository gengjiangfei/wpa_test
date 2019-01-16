#include "includes.h"
#include "common.h"
#include "crypto/aes.h"
#include "crypto/aes_wrap.h"
#include "crypto/crypto.h"
#include "crypto/random.h"
#include "crypto/aes_siv.h"
#include "common/ieee802_11_defs.h"
#include "eap_common/eap_defs.h"
#include "eapol_supp/eapol_supp_sm.h"
#include "wpa.h"
#include "eloop.h"
#include "preauth.h"
#include "pmksa_cache.h"
#include "wpa_i.h"
#include "wpa_ie.h"


static const u8 null_rsc[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

struct wpa_gtk_data {
    enum wpa_alg alg;
    int tx, key_rsc_len, keyidx;
    u8 gtk[32];
    int gtk_len;
};

/**
 * wpa_sm_set_own_addr - Set own MAC address
 * @sm: Pointer to WPA state machine data from wpa_sm_init()
 * @addr: Own MAC address
 */
void wpa_sm_set_own_addr(struct wpa_sm *sm, const u8 *addr)
{
    if (sm)
        os_memcpy(sm->own_addr, addr, ETH_ALEN);
}

static u32 wpa_key_mgmt_suite(struct wpa_sm *sm)
{
    switch (sm->key_mgmt) {
    case WPA_KEY_MGMT_IEEE8021X:
        return ((sm->proto == WPA_PROTO_RSN ||
             sm->proto == WPA_PROTO_OSEN) ?
            RSN_AUTH_KEY_MGMT_UNSPEC_802_1X :
            WPA_AUTH_KEY_MGMT_UNSPEC_802_1X);
    case WPA_KEY_MGMT_PSK:
        return (sm->proto == WPA_PROTO_RSN ?
            RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X :
            WPA_AUTH_KEY_MGMT_PSK_OVER_802_1X);
    case WPA_KEY_MGMT_CCKM:
        return (sm->proto == WPA_PROTO_RSN ?
            RSN_AUTH_KEY_MGMT_CCKM:
            WPA_AUTH_KEY_MGMT_CCKM);
    case WPA_KEY_MGMT_WPA_NONE:
        return WPA_AUTH_KEY_MGMT_NONE;
    case WPA_KEY_MGMT_IEEE8021X_SUITE_B:
        return RSN_AUTH_KEY_MGMT_802_1X_SUITE_B;
    case WPA_KEY_MGMT_IEEE8021X_SUITE_B_192:
        return RSN_AUTH_KEY_MGMT_802_1X_SUITE_B_192;
    default:
        return 0;
    }
}


/**
 * wpa_sm_set_assoc_wpa_ie_default - Generate own WPA/RSN IE from configuration
 * @sm: Pointer to WPA state machine data from wpa_sm_init()
 * @wpa_ie: Pointer to buffer for WPA/RSN IE
 * @wpa_ie_len: Pointer to the length of the wpa_ie buffer
 * Returns: 0 on success, -1 on failure
 */
int wpa_sm_set_assoc_wpa_ie_default(struct wpa_sm *sm, u8 *wpa_ie,size_t *wpa_ie_len)
{
    int res;

    if (sm == NULL)
        return -1;

    res = wpa_gen_wpa_ie(sm, wpa_ie, *wpa_ie_len);
    if (res < 0)
        return -1;
    *wpa_ie_len = res;

    wpa_hexdump(MSG_ERROR, "WPA: Set own WPA IE default",wpa_ie, *wpa_ie_len);

    if (sm->assoc_wpa_ie == NULL)
    {
        /*
         * Make a copy of the WPA/RSN IE so that 4-Way Handshake gets
         * the correct version of the IE even if PMKSA caching is
         * aborted (which would remove PMKID from IE generation).
         */
        sm->assoc_wpa_ie = os_malloc(*wpa_ie_len);
        if (sm->assoc_wpa_ie == NULL)
            return -1;

        os_memcpy(sm->assoc_wpa_ie, wpa_ie, *wpa_ie_len);
        sm->assoc_wpa_ie_len = *wpa_ie_len;
    } 
    else
    {
        wpa_hexdump(MSG_ERROR,"WPA: Leave previously set WPA IE default",
                      sm->assoc_wpa_ie, sm->assoc_wpa_ie_len);
    }

    return 0;
}

static int wpa_derive_ptk(struct wpa_sm *sm, const unsigned char *src_addr,
              const struct wpa_eapol_key *key, struct wpa_ptk *ptk)
{
printf("############gjf==> %s(%d)##############\n",__func__,__LINE__);
printf("pmk_len=%ld,key_mgmt=%d,pairwise_cipher=%d\n",
        sm->pmk_len,sm->key_mgmt,sm->pairwise_cipher);

wpa_hexdump(MSG_ERROR, "WPA: PMK",sm->pmk,sm->pmk_len);
wpa_hexdump(MSG_ERROR, "WPA: snonce",sm->snonce,WPA_NONCE_LEN);
wpa_hexdump(MSG_ERROR, "WPA: key_nonce",key->key_nonce,WPA_NONCE_LEN);

printf("%s(%d): own_addr="MACSTR"\n",__func__,__LINE__,MAC2STR(sm->own_addr));
printf("%s(%d): bssid="MACSTR"\n",__func__,__LINE__,MAC2STR(sm->bssid));
printf("#######################################\n");

    return wpa_pmk_to_ptk(sm->pmk, sm->pmk_len, "Pairwise key expansion",
                  sm->own_addr, sm->bssid, sm->snonce,
                  key->key_nonce, ptk, sm->key_mgmt,
                  sm->pairwise_cipher);
}


/**
 * wpa_sm_set_pmk_from_pmksa - Set PMK based on the current PMKSA
 * @sm: Pointer to WPA state machine data from wpa_sm_init()
 *
 * Take the PMK from the current PMKSA into use. If no PMKSA is active, the PMK
 * will be cleared.
 */
void wpa_sm_set_pmk_from_pmksa(struct wpa_sm *sm)
{
    if (sm == NULL)
        return;

    if (sm->cur_pmksa) {
        sm->pmk_len = sm->cur_pmksa->pmk_len;
        os_memcpy(sm->pmk, sm->cur_pmksa->pmk, sm->pmk_len);
    } else {
        sm->pmk_len = PMK_LEN;
        os_memset(sm->pmk, 0, PMK_LEN);
    }
}


static void wpa_supplicant_key_mgmt_set_pmk(struct wpa_sm *sm)
{
    if (wpa_sm_key_mgmt_set_pmk(sm, sm->pmk, sm->pmk_len))
    {
        wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,"RSN: Cannot set PMK for key management offload");
    }
}

static int wpa_supplicant_get_pmk(struct wpa_sm *sm,
                  const unsigned char *src_addr,
                  const u8 *pmkid)
{
    int abort_cached = 0;
printf("%s(%d):\n",__func__,__LINE__);
    if (pmkid && !sm->cur_pmksa)
    {
        /* When using drivers that generate RSN IE, wpa_supplicant may
         * not have enough time to get the association information
         * event before receiving this 1/4 message, so try to find a
         * matching PMKSA cache entry here. */
        sm->cur_pmksa = pmksa_cache_get(sm->pmksa, src_addr, pmkid,NULL);
        if (sm->cur_pmksa)
        {
            wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
                "RSN: found matching PMKID from PMKSA cache");
        }
        else
        {
            wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
                "RSN: no matching PMKID found");
            abort_cached = 1;
        }
    }

    if (pmkid && sm->cur_pmksa &&
        os_memcmp_const(pmkid, sm->cur_pmksa->pmkid, PMKID_LEN) == 0)
    {
        wpa_hexdump(MSG_DEBUG, "RSN: matched PMKID", pmkid, PMKID_LEN);
        wpa_sm_set_pmk_from_pmksa(sm);
        wpa_hexdump_key(MSG_DEBUG, "RSN: PMK from PMKSA cache",
                sm->pmk, sm->pmk_len);
//      eapol_sm_notify_cached(sm->eapol);
    }
    else if (wpa_key_mgmt_wpa_ieee8021x(sm->key_mgmt) && sm->eapol)
    {
        int res, pmk_len;

        if (wpa_key_mgmt_sha384(sm->key_mgmt))
            pmk_len = PMK_LEN_SUITE_B_192;
        else
            pmk_len = PMK_LEN;
        res = eapol_sm_get_key(sm->eapol, sm->pmk, pmk_len);
        if (res)
        {
            if (pmk_len == PMK_LEN)
            {
                /*
                 * EAP-LEAP is an exception from other EAP
                 * methods: it uses only 16-byte PMK.
                 */
                res = eapol_sm_get_key(sm->eapol, sm->pmk, 16);
                pmk_len = 16;
            }
        } 
        else 
        {
            ;
        }
        if (res == 0) 
        {
            struct rsn_pmksa_cache_entry *sa = NULL;
            const u8 *fils_cache_id = NULL;
            wpa_hexdump_key(MSG_DEBUG, "WPA: PMK from EAPOL state "
                    "machines", sm->pmk, pmk_len);
            sm->pmk_len = pmk_len;
            wpa_supplicant_key_mgmt_set_pmk(sm);
            if (sm->proto == WPA_PROTO_RSN &&
                !wpa_key_mgmt_suite_b(sm->key_mgmt) &&
                !wpa_key_mgmt_ft(sm->key_mgmt)) {
                sa = pmksa_cache_add(sm->pmksa,
                             sm->pmk, pmk_len, NULL,
                             NULL, 0,
                             src_addr, sm->own_addr,
                             sm->network_ctx,
                             sm->key_mgmt,
                             fils_cache_id);
            }
            if (!sm->cur_pmksa && pmkid &&
                pmksa_cache_get(sm->pmksa, src_addr, pmkid, NULL))
            {
                wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
                    "RSN: the new PMK matches with the "
                    "PMKID");
                abort_cached = 0;
            } else if (sa && !sm->cur_pmksa && pmkid) {
                /*
                 * It looks like the authentication server
                 * derived mismatching MSK. This should not
                 * really happen, but bugs happen.. There is not
                 * much we can do here without knowing what
                 * exactly caused the server to misbehave.
                 */
                wpa_msg(sm->ctx->msg_ctx, MSG_INFO,
                    "RSN: PMKID mismatch - authentication server may have derived different MSK?!");
                return -1;
            }

            if (!sm->cur_pmksa)
                sm->cur_pmksa = sa;
        } else {
            wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
                "WPA: Failed to get master session key from "
                "EAPOL state machines - key handshake "
                "aborted");
            if (sm->cur_pmksa) {
                wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
                    "RSN: Cancelled PMKSA caching "
                    "attempt");
                sm->cur_pmksa = NULL;
                abort_cached = 1;
            } else if (!abort_cached) {
                return -1;
            }
        }
    }

    if (abort_cached && wpa_key_mgmt_wpa_ieee8021x(sm->key_mgmt) &&
        !wpa_key_mgmt_suite_b(sm->key_mgmt) &&
        !wpa_key_mgmt_ft(sm->key_mgmt) && sm->key_mgmt != WPA_KEY_MGMT_OSEN)
    {
        /* Send EAPOL-Start to trigger full EAP authentication. */
        u8 *buf;
        size_t buflen;

        wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
            "RSN: no PMKSA entry found - trigger "
            "full EAP authentication");
        buf = wpa_sm_alloc_eapol(sm, IEEE802_1X_TYPE_EAPOL_START,
                     NULL, 0, &buflen, NULL);
        if (buf) {
            wpa_sm_ether_send(sm, sm->bssid, ETH_P_EAPOL,
                      buf, buflen);
            os_free(buf);
            return -2;
        }

        return -1;
    }

    return 0;
}



/**
 * wpa_eapol_key_send - Send WPA/RSN EAPOL-Key message
 * @sm: Pointer to WPA state machine data from wpa_sm_init()
 * @ptk: PTK for Key Confirmation/Encryption Key
 * @ver: Version field from Key Info
 * @dest: Destination address for the frame
 * @proto: Ethertype (usually ETH_P_EAPOL)
 * @msg: EAPOL-Key message
 * @msg_len: Length of message
 * @key_mic: Pointer to the buffer to which the EAPOL-Key MIC is written
 * Returns: >= 0 on success, < 0 on failure
 */
int wpa_eapol_key_send(struct wpa_sm *sm, struct wpa_ptk *ptk,
               int ver, const u8 *dest, u16 proto,
               u8 *msg, size_t msg_len, u8 *key_mic)
{
    int ret = -1;
    size_t mic_len = wpa_mic_len(sm->key_mgmt);

    if (is_zero_ether_addr(dest) && is_zero_ether_addr(sm->bssid)) {
        /*
         * Association event was not yet received; try to fetch
         * BSSID from the driver.
         */
        if (wpa_sm_get_bssid(sm, sm->bssid) < 0) {
            wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
                "WPA: Failed to read BSSID for "
                "EAPOL-Key destination address");
        } else {
            dest = sm->bssid;
            printf("WPA: Use BSSID (" MACSTR") as the destination for EAPOL-Key",MAC2STR(dest));
        }
    }

    if (mic_len) {
        if (key_mic && (!ptk || !ptk->kck_len))
            goto out;

        if (key_mic &&
            wpa_eapol_key_mic(ptk->kck, ptk->kck_len, sm->key_mgmt, ver,
                      msg, msg_len, key_mic)) {
            wpa_msg(sm->ctx->msg_ctx, MSG_ERROR,
                "WPA: Failed to generate EAPOL-Key version %d key_mgmt 0x%x MIC",
                ver, sm->key_mgmt);
            goto out;
        }
        if (ptk)
            wpa_hexdump_key(MSG_DEBUG, "WPA: KCK",ptk->kck, ptk->kck_len);
        
        wpa_hexdump(MSG_DEBUG, "WPA: Derived Key MIC",key_mic, mic_len);
    }
    else
    {
        goto out;
    }

    wpa_hexdump(MSG_MSGDUMP, "WPA: TX EAPOL-Key", msg, msg_len);
    ret = wpa_sm_ether_send(sm, dest, proto, msg, msg_len);
    eapol_sm_notify_tx_eapol_key(sm->eapol);
out:
    os_free(msg);
    return ret;
}


/**
 * wpa_supplicant_send_2_of_4 - Send message 2 of WPA/RSN 4-Way Handshake
 * @sm: Pointer to WPA state machine data from wpa_sm_init()
 * @dst: Destination address for the frame
 * @key: Pointer to the EAPOL-Key frame header
 * @ver: Version bits from EAPOL-Key Key Info
 * @nonce: Nonce value for the EAPOL-Key frame
 * @wpa_ie: WPA/RSN IE
 * @wpa_ie_len: Length of the WPA/RSN IE
 * @ptk: PTK to use for keyed hash and encryption
 * Returns: >= 0 on success, < 0 on failure
 */
int wpa_supplicant_send_2_of_4(struct wpa_sm *sm, const unsigned char *dst,
                   const struct wpa_eapol_key *key,
                   int ver, const u8 *nonce,
                   const u8 *wpa_ie, size_t wpa_ie_len,
                   struct wpa_ptk *ptk)
{
    size_t mic_len, hdrlen, rlen;
    struct wpa_eapol_key *reply;
    u8 *rbuf, *key_mic;
    u8 *rsn_ie_buf = NULL;
    u16 key_info;

    if (wpa_ie == NULL) 
    {
        printf("WPA: No wpa_ie set - ""cannot generate msg 2/4\n");
        return -1;
    }

    wpa_hexdump(MSG_DEBUG, "WPA: WPA IE for msg 2/4", wpa_ie, wpa_ie_len);
    
/*************STA构造eapol-key报文******************/
    mic_len = wpa_mic_len(sm->key_mgmt);
    hdrlen = sizeof(*reply) + mic_len + 2;
    rbuf = wpa_sm_alloc_eapol(sm, IEEE802_1X_TYPE_EAPOL_KEY,
                  NULL, hdrlen + wpa_ie_len,
                  &rlen, (void *) &reply);
    if (rbuf == NULL) {
        os_free(rsn_ie_buf);
        return -1;
    }

    reply->type = (sm->proto == WPA_PROTO_RSN ||
               sm->proto == WPA_PROTO_OSEN) ?
        EAPOL_KEY_TYPE_RSN : EAPOL_KEY_TYPE_WPA;
    
    key_info = ver | WPA_KEY_INFO_KEY_TYPE;
    if (mic_len)
        key_info |= WPA_KEY_INFO_MIC;
    else
        key_info |= WPA_KEY_INFO_ENCR_KEY_DATA;
    
    WPA_PUT_BE16(reply->key_info, key_info);
    if (sm->proto == WPA_PROTO_RSN || sm->proto == WPA_PROTO_OSEN)
        WPA_PUT_BE16(reply->key_length, 0);
    else
        os_memcpy(reply->key_length, key->key_length, 2);
    os_memcpy(reply->replay_counter, key->replay_counter,
          WPA_REPLAY_COUNTER_LEN);
    wpa_hexdump(MSG_DEBUG, "WPA: Replay Counter", reply->replay_counter,
            WPA_REPLAY_COUNTER_LEN);

    key_mic = (u8 *) (reply + 1);
    WPA_PUT_BE16(key_mic + mic_len, wpa_ie_len); /* Key Data Length */
    os_memcpy(key_mic + mic_len + 2, wpa_ie, wpa_ie_len); /* Key Data */
    os_free(rsn_ie_buf);

    os_memcpy(reply->key_nonce, nonce, WPA_NONCE_LEN);

    wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG, "WPA: Sending EAPOL-Key 2/4");
    return wpa_eapol_key_send(sm, ptk, ver, dst, ETH_P_EAPOL, rbuf, rlen,key_mic);
}

static void wpa_supplicant_process_1_of_4(struct wpa_sm *sm,
                      const unsigned char *src_addr,
                      const struct wpa_eapol_key *key,
                      u16 ver, const u8 *key_data,
                      size_t key_data_len)
{
    struct wpa_eapol_ie_parse ie;
    struct wpa_ptk *ptk;
    int res;
    u8 *kde, *kde_buf = NULL;
    size_t kde_len;
    printf("%s(%d):\n",__func__,__LINE__);

//  if (wpa_sm_get_network_ctx(sm) == NULL) 
//  {
//      printf("WPA: No SSID info found (msg 1 of 4)\n");
//      return;
//  }

//  wpa_sm_set_state(sm, WPA_4WAY_HANDSHAKE);
    printf("WPA: RX message 1 of 4-Way Handshake from " MACSTR " (ver=%d)\n", MAC2STR(src_addr), ver);

    os_memset(&ie, 0, sizeof(ie));

    if (sm->proto == WPA_PROTO_RSN || sm->proto == WPA_PROTO_OSEN) 
    {
        /* RSN: msg 1/4 should contain PMKID for the selected PMK */
        wpa_hexdump(MSG_ERROR, "RSN: msg 1/4 key data",key_data, key_data_len);
        if (wpa_supplicant_parse_ies(key_data, key_data_len, &ie) < 0)//ie获取RSN信息元素的位置
            goto failed;
        if (ie.pmkid)
        {
            wpa_hexdump(MSG_ERROR, "RSN: PMKID from Authenticator", ie.pmkid, PMKID_LEN);
        }
    }

    res = wpa_supplicant_get_pmk(sm, src_addr, ie.pmkid);//获取PMK，PMK在程序启动时根据配置信息生成
    if (res == -2)
    {
        printf("RSN: Do not reply to "
            "msg 1/4 - requesting full EAP authentication\n");
        return;
    }
    if (res)
        goto failed;
    
    if (sm->renew_snonce)
    {
        if (random_get_bytes(sm->snonce, WPA_NONCE_LEN))//产生随机数Snonce
        {
            printf("WPA: Failed to get random data for SNonce\n");
            goto failed;
        }
        sm->renew_snonce = 0;
        wpa_hexdump(MSG_ERROR, "WPA: Renewed SNonce",sm->snonce, WPA_NONCE_LEN);
    }

    /* Calculate PTK which will be stored as a temporary PTK until it has
     * been verified when processing message 3/4. */
    ptk = &sm->tptk;
    wpa_derive_ptk(sm, src_addr, key, ptk);//生成PTK，指导第三次握手成功后，PTK被安装到Driver中
    if (sm->pairwise_cipher == WPA_CIPHER_TKIP)
    {
        u8 buf[8];
        /* Supplicant: swap tx/rx Mic keys */
        os_memcpy(buf, &ptk->tk[16], 8);
        os_memcpy(&ptk->tk[16], &ptk->tk[24], 8);
        os_memcpy(&ptk->tk[24], buf, 8);
        os_memset(buf, 0, sizeof(buf));
    }
    sm->tptk_set = 1;
    sm->tk_to_set = 1;

    kde = sm->assoc_wpa_ie;
    kde_len = sm->assoc_wpa_ie_len;


    if (wpa_supplicant_send_2_of_4(sm, sm->bssid, key, ver, sm->snonce,
                       kde, kde_len, ptk) < 0)
        goto failed;

    os_free(kde_buf);
    os_memcpy(sm->anonce, key->key_nonce, WPA_NONCE_LEN);
    return;

failed:
    os_free(kde_buf);
    wpa_sm_deauthenticate(sm, WLAN_REASON_UNSPECIFIED);//握手失败，发送deauth信息
}



static void wpa_supplicant_key_neg_complete(struct wpa_sm *sm,
                        const u8 *addr, int secure)
{
    wpa_msg(sm->ctx->msg_ctx, MSG_INFO,
        "WPA: Key negotiation completed with "
        MACSTR " [PTK=%s GTK=%s]", MAC2STR(addr),
        wpa_cipher_txt(sm->pairwise_cipher),
        wpa_cipher_txt(sm->group_cipher));
//  wpa_sm_cancel_auth_timeout(sm);
    wpa_sm_set_state(sm, WPA_COMPLETED);

    if (secure) {
//      wpa_sm_mlme_setprotection(
//          sm, addr, MLME_SETPROTECTION_PROTECT_TYPE_RX_TX,
//          MLME_SETPROTECTION_KEY_TYPE_PAIRWISE);
        eapol_sm_notify_portValid(sm->eapol, TRUE);
        if (wpa_key_mgmt_wpa_psk(sm->key_mgmt))
            eapol_sm_notify_eap_success(sm->eapol, TRUE);
        /*
         * Start preauthentication after a short wait to avoid a
         * possible race condition between the data receive and key
         * configuration after the 4-Way Handshake. This increases the
         * likelihood of the first preauth EAPOL-Start frame getting to
         * the target AP.
         */
//      eloop_register_timeout(1, 0, wpa_sm_start_preauth, sm, NULL); //add by gjf
    }

    if (sm->cur_pmksa && sm->cur_pmksa->opportunistic) {
        wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
            "RSN: Authenticator accepted "
            "opportunistic PMKSA entry - marking it valid");
        sm->cur_pmksa->opportunistic = 0;
    }
}

static int wpa_supplicant_gtk_tx_bit_workaround(const struct wpa_sm *sm,int tx)
{
    if (tx && sm->pairwise_cipher != WPA_CIPHER_NONE)
    {
        /* Ignore Tx bit for GTK if a pairwise key is used. One AP
         * seemed to set this bit (incorrectly, since Tx is only when
         * doing Group Key only APs) and without this workaround, the
         * data connection does not work because wpa_supplicant
         * configured non-zero keyidx to be used for unicast. */
        wpa_msg(sm->ctx->msg_ctx, MSG_INFO,
            "WPA: Tx bit set for GTK, but pairwise "
            "keys are used - ignore Tx bit");
        return 0;
    }
    return tx;
}


static int wpa_supplicant_rsc_relaxation(const struct wpa_sm *sm,const u8 *rsc)
{
    int rsclen;

    if (!sm->wpa_rsc_relaxation)
        return 0;

    rsclen = wpa_cipher_rsc_len(sm->group_cipher);

    /*
     * Try to detect RSC (endian) corruption issue where the AP sends
     * the RSC bytes in EAPOL-Key message in the wrong order, both if
     * it's actually a 6-byte field (as it should be) and if it treats
     * it as an 8-byte field.
     * An AP model known to have this bug is the Sapido RB-1632.
     */
    if (rsclen == 6 && ((rsc[5] && !rsc[0]) || rsc[6] || rsc[7])) {
        wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
            "RSC %02x%02x%02x%02x%02x%02x%02x%02x is likely bogus, using 0",
            rsc[0], rsc[1], rsc[2], rsc[3],
            rsc[4], rsc[5], rsc[6], rsc[7]);

        return 1;
    }

    return 0;
}


static int wpa_supplicant_check_group_cipher(struct wpa_sm *sm,
                         int group_cipher,
                         int keylen, int maxkeylen,
                         int *key_rsc_len,
                         enum wpa_alg *alg)
{
    int klen;

    *alg = wpa_cipher_to_alg(group_cipher);
    if (*alg == WPA_ALG_NONE) {
        wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
            "WPA: Unsupported Group Cipher %d",
            group_cipher);
        return -1;
    }
    *key_rsc_len = wpa_cipher_rsc_len(group_cipher);

    klen = wpa_cipher_key_len(group_cipher);
    if (keylen != klen || maxkeylen < klen) {
        wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
            "WPA: Unsupported %s Group Cipher key length %d (%d)",
            wpa_cipher_txt(group_cipher), keylen, maxkeylen);
        return -1;
    }
    return 0;
}


static int wpa_supplicant_install_gtk(struct wpa_sm *sm,
                      const struct wpa_gtk_data *gd,
                      const u8 *key_rsc)
{
    const u8 *_gtk = gd->gtk;
    u8 gtk_buf[32];

    wpa_hexdump_key(MSG_DEBUG, "WPA: Group Key", gd->gtk, gd->gtk_len);
    wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
        "WPA: Installing GTK to the driver (keyidx=%d tx=%d len=%d)",
        gd->keyidx, gd->tx, gd->gtk_len);
    wpa_hexdump(MSG_DEBUG, "WPA: RSC", key_rsc, gd->key_rsc_len);
    if (sm->group_cipher == WPA_CIPHER_TKIP)
    {
        /* Swap Tx/Rx keys for Michael MIC */
        os_memcpy(gtk_buf, gd->gtk, 16);
        os_memcpy(gtk_buf + 16, gd->gtk + 24, 8);
        os_memcpy(gtk_buf + 24, gd->gtk + 16, 8);
        _gtk = gtk_buf;
    }
    if (sm->pairwise_cipher == WPA_CIPHER_NONE)
    {
        if (wpa_sm_set_key(sm, gd->alg, NULL,
                   gd->keyidx, 1, key_rsc, gd->key_rsc_len,
                   _gtk, gd->gtk_len) < 0) {
            wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
                "WPA: Failed to set GTK to the driver "
                "(Group only)");
            os_memset(gtk_buf, 0, sizeof(gtk_buf));
            return -1;
        }
    }
    else if (wpa_sm_set_key(sm, gd->alg, broadcast_ether_addr,
                  gd->keyidx, gd->tx, key_rsc, gd->key_rsc_len,
                  _gtk, gd->gtk_len) < 0)
    {
        wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
            "WPA: Failed to set GTK to "
            "the driver (alg=%d keylen=%d keyidx=%d)",
            gd->alg, gd->gtk_len, gd->keyidx);
        os_memset(gtk_buf, 0, sizeof(gtk_buf));
        return -1;
    }
    os_memset(gtk_buf, 0, sizeof(gtk_buf));

    return 0;
}

static int wpa_supplicant_pairwise_gtk(struct wpa_sm *sm,
                       const struct wpa_eapol_key *key,
                       const u8 *gtk, size_t gtk_len,
                       int key_info)
{
    struct wpa_gtk_data gd;
    const u8 *key_rsc;

    /*
     * IEEE Std 802.11i-2004 - 8.5.2 EAPOL-Key frames - Figure 43x
     * GTK KDE format:
     * KeyID[bits 0-1], Tx [bit 2], Reserved [bits 3-7]
     * Reserved [bits 0-7]
     * GTK
     */
printf("%s(%d):\n",__func__,__LINE__);

    os_memset(&gd, 0, sizeof(gd));
    wpa_hexdump_key(MSG_DEBUG, "RSN: received GTK in pairwise handshake",
            gtk, gtk_len);

    if (gtk_len < 2 || gtk_len - 2 > sizeof(gd.gtk))
    {
        printf("%s(%d):\n",__func__,__LINE__);
        return -1;
    }

    gd.keyidx = gtk[0] & 0x3;
    gd.tx = wpa_supplicant_gtk_tx_bit_workaround(sm,
                             !!(gtk[0] & BIT(2)));
    gtk += 2;
    gtk_len -= 2;

    os_memcpy(gd.gtk, gtk, gtk_len);
    gd.gtk_len = gtk_len;

    key_rsc = key->key_rsc;
    if (wpa_supplicant_rsc_relaxation(sm, key->key_rsc))
        key_rsc = null_rsc;

    if (sm->group_cipher != WPA_CIPHER_GTK_NOT_USED &&
        (wpa_supplicant_check_group_cipher(sm, sm->group_cipher,
                           gtk_len, gtk_len,
                           &gd.key_rsc_len, &gd.alg) ||
         wpa_supplicant_install_gtk(sm, &gd, key_rsc)))
    {
        wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
            "RSN: Failed to install GTK");
        os_memset(&gd, 0, sizeof(gd));
        
          printf("%s(%d):\n",__func__,__LINE__);
          return -1;
    }
    os_memset(&gd, 0, sizeof(gd));

    wpa_supplicant_key_neg_complete(sm, sm->bssid,key_info & WPA_KEY_INFO_SECURE);
    
printf("%s(%d):\n",__func__,__LINE__);

    return 0;
}

static int wpa_supplicant_install_ptk(struct wpa_sm *sm,
                      const struct wpa_eapol_key *key)
{
    int keylen, rsclen;
    enum wpa_alg alg;
    const u8 *key_rsc;

    if (!sm->tk_to_set) {
        wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
            "WPA: Do not re-install same PTK to the driver");
        return 0;
    }

    wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
        "WPA: Installing PTK to the driver");

    if (sm->pairwise_cipher == WPA_CIPHER_NONE) {
        wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG, "WPA: Pairwise Cipher "
            "Suite: NONE - do not use pairwise keys");
        return 0;
    }

    if (!wpa_cipher_valid_pairwise(sm->pairwise_cipher)) {
        wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
            "WPA: Unsupported pairwise cipher %d",
            sm->pairwise_cipher);
        return -1;
    }

    alg = wpa_cipher_to_alg(sm->pairwise_cipher);
    keylen = wpa_cipher_key_len(sm->pairwise_cipher);
    rsclen = wpa_cipher_rsc_len(sm->pairwise_cipher);

    if (sm->proto == WPA_PROTO_RSN || sm->proto == WPA_PROTO_OSEN) {
        key_rsc = null_rsc;
    } else {
        key_rsc = key->key_rsc;
        wpa_hexdump(MSG_DEBUG, "WPA: RSC", key_rsc, rsclen);
    }

    if (wpa_sm_set_key(sm, alg, sm->bssid, 0, 1, key_rsc, rsclen,
               sm->ptk.tk, keylen) < 0) {
        wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
            "WPA: Failed to set PTK to the "
            "driver (alg=%d keylen=%d bssid=" MACSTR ")",
            alg, keylen, MAC2STR(sm->bssid));
        return -1;
    }

    /* TK is not needed anymore in supplicant */
    os_memset(sm->ptk.tk, 0, WPA_TK_MAX_LEN);
    sm->tk_to_set = 0;

//  if (sm->wpa_ptk_rekey) {
//      eloop_cancel_timeout(wpa_sm_rekey_ptk, sm, NULL);
//      eloop_register_timeout(sm->wpa_ptk_rekey, 0, wpa_sm_rekey_ptk,
//                     sm, NULL);
//  }
printf("%s(%d): install ptk OK!\n",__func__,__LINE__);
    return 0;
}

/**
 * wpa_supplicant_send_4_of_4 - Send message 4 of WPA/RSN 4-Way Handshake
 * @sm: Pointer to WPA state machine data from wpa_sm_init()
 * @dst: Destination address for the frame
 * @key: Pointer to the EAPOL-Key frame header
 * @ver: Version bits from EAPOL-Key Key Info
 * @key_info: Key Info
 * @ptk: PTK to use for keyed hash and encryption
 * Returns: >= 0 on success, < 0 on failure
 */
int wpa_supplicant_send_4_of_4(struct wpa_sm *sm, const unsigned char *dst,
                   const struct wpa_eapol_key *key,
                   u16 ver, u16 key_info,
                   struct wpa_ptk *ptk)
{
    size_t mic_len, hdrlen, rlen;
    struct wpa_eapol_key *reply;
    u8 *rbuf, *key_mic;

    mic_len = wpa_mic_len(sm->key_mgmt);
    hdrlen = sizeof(*reply) + mic_len + 2;
    rbuf = wpa_sm_alloc_eapol(sm, IEEE802_1X_TYPE_EAPOL_KEY, NULL,
                  hdrlen, &rlen, (void *) &reply);
    if (rbuf == NULL)
        return -1;

    reply->type = (sm->proto == WPA_PROTO_RSN ||
               sm->proto == WPA_PROTO_OSEN) ?
        EAPOL_KEY_TYPE_RSN : EAPOL_KEY_TYPE_WPA;
    key_info &= WPA_KEY_INFO_SECURE;
    key_info |= ver | WPA_KEY_INFO_KEY_TYPE;
    if (mic_len)
        key_info |= WPA_KEY_INFO_MIC;
    else
        key_info |= WPA_KEY_INFO_ENCR_KEY_DATA;
    WPA_PUT_BE16(reply->key_info, key_info);
    if (sm->proto == WPA_PROTO_RSN || sm->proto == WPA_PROTO_OSEN)
        WPA_PUT_BE16(reply->key_length, 0);
    else
        os_memcpy(reply->key_length, key->key_length, 2);
    os_memcpy(reply->replay_counter, key->replay_counter,
          WPA_REPLAY_COUNTER_LEN);

    key_mic = (u8 *) (reply + 1);
    WPA_PUT_BE16(key_mic + mic_len, 0);

    wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG, "WPA: Sending EAPOL-Key 4/4");
    return wpa_eapol_key_send(sm, ptk, ver, dst, ETH_P_EAPOL, rbuf, rlen,
                  key_mic);
}


static void wpa_supplicant_process_3_of_4(struct wpa_sm *sm,
                      const struct wpa_eapol_key *key,
                      u16 ver, const u8 *key_data,
                      size_t key_data_len)
{
    u16 key_info, keylen;
    struct wpa_eapol_ie_parse ie;
printf("%s(%d): WPA: RX message 3 of 4-Way!\n",__func__,__LINE__);
//  wpa_sm_set_state(sm, WPA_4WAY_HANDSHAKE);
    wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG, "WPA: RX message 3 of 4-Way "
        "Handshake from " MACSTR " (ver=%d)", MAC2STR(sm->bssid), ver);

    key_info = WPA_GET_BE16(key->key_info);

    wpa_hexdump(MSG_DEBUG, "WPA: IE KeyData", key_data, key_data_len);
    if (wpa_supplicant_parse_ies(key_data, key_data_len, &ie) < 0)
        goto failed;
    if (ie.gtk && !(key_info & WPA_KEY_INFO_ENCR_KEY_DATA)) {
        wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
            "WPA: GTK IE in unencrypted key data");
        goto failed;
    }
/* 检查ap Beacon帧中的WPA、RSN信息元素是否和当前EAPOL中的WPA、RSN配置相同 */
//  if (wpa_supplicant_validate_ie(sm, sm->bssid, &ie) < 0)
//      goto failed;

    if (os_memcmp(sm->anonce, key->key_nonce, WPA_NONCE_LEN) != 0) {
        wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
            "WPA: ANonce from message 1 of 4-Way Handshake "
            "differs from 3 of 4-Way Handshake - drop packet (src="
            MACSTR ")", MAC2STR(sm->bssid));
        goto failed;
    }

    keylen = WPA_GET_BE16(key->key_length);
    if (keylen != wpa_cipher_key_len(sm->pairwise_cipher)) {
        wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
            "WPA: Invalid %s key length %d (src=" MACSTR
            ")", wpa_cipher_txt(sm->pairwise_cipher), keylen,
            MAC2STR(sm->bssid));
        goto failed;
    }

    if (wpa_supplicant_send_4_of_4(sm, sm->bssid, key, ver, key_info,
                       &sm->ptk) < 0) {
        goto failed;
    }

    /* SNonce was successfully used in msg 3/4, so mark it to be renewed
     * for the next 4-Way Handshake. If msg 3 is received again, the old
     * SNonce will still be used to avoid changing PTK. */
    sm->renew_snonce = 1;

    if (key_info & WPA_KEY_INFO_INSTALL) {
        if (wpa_supplicant_install_ptk(sm, key))
            goto failed;
    }

//  if (key_info & WPA_KEY_INFO_SECURE) {
//printf("*** %s(%d):Current Driver Unrealized!****\n",__func__,__LINE__);
//      wpa_sm_mlme_setprotection(
//          sm, sm->bssid, MLME_SETPROTECTION_PROTECT_TYPE_RX,
//          MLME_SETPROTECTION_KEY_TYPE_PAIRWISE);
//      eapol_sm_notify_portValid(sm->eapol, TRUE);
//  }

//  wpa_sm_set_state(sm, WPA_GROUP_HANDSHAKE);


    if (sm->group_cipher == WPA_CIPHER_GTK_NOT_USED) {
        wpa_supplicant_key_neg_complete(sm, sm->bssid,
                        key_info & WPA_KEY_INFO_SECURE);

    } 
    else if (ie.gtk && wpa_supplicant_pairwise_gtk(sm, key,ie.gtk, ie.gtk_len, key_info) < 0)
    {
        wpa_msg(sm->ctx->msg_ctx, MSG_INFO,
            "RSN: Failed to configure GTK");
        goto failed;
    }

    if (ie.gtk)
        wpa_sm_set_rekey_offload(sm);

//  if (sm->proto == WPA_PROTO_RSN && wpa_key_mgmt_suite_b(sm->key_mgmt)) {
//      struct rsn_pmksa_cache_entry *sa;

//      sa = pmksa_cache_add(sm->pmksa, sm->pmk, sm->pmk_len, NULL,
//                   sm->ptk.kck, sm->ptk.kck_len,
//                   sm->bssid, sm->own_addr,
//                   sm->network_ctx, sm->key_mgmt, NULL);
//      if (!sm->cur_pmksa)
//          sm->cur_pmksa = sa;
//  }
printf("%s(%d):****\n",__func__,__LINE__);

    sm->msg_3_of_4_ok = 1;
    return;

failed:
    wpa_sm_deauthenticate(sm, WLAN_REASON_UNSPECIFIED);
    printf("############ wpa_sm_deauthenticate  ############\n");
}


/* Decrypt RSN EAPOL-Key key data (RC4 or AES-WRAP) */
static int wpa_supplicant_decrypt_key_data(struct wpa_sm *sm,
                       struct wpa_eapol_key *key,
                       size_t mic_len, u16 ver,
                       u8 *key_data, size_t *key_data_len)
{
    wpa_hexdump(MSG_DEBUG, "RSN: encrypted key data",key_data, *key_data_len);
    if (!sm->ptk_set)
    {
        wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
            "WPA: PTK not available, cannot decrypt EAPOL-Key Key "
            "Data");
        return -1;
    }

    /* Decrypt key data here so that this operation does not need
     * to be implemented separately for each message type. */
    if (ver == WPA_KEY_INFO_TYPE_HMAC_MD5_RC4 && sm->ptk.kek_len == 16)
    {
        wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
            "WPA: RC4 not supported in the build");
        return -1;
    }
    else if (ver == WPA_KEY_INFO_TYPE_HMAC_SHA1_AES)
    {
        u8 *buf;
        if (*key_data_len < 8 || *key_data_len % 8) 
        {
            wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
                "WPA: Unsupported AES-WRAP len %u",
                (unsigned int) *key_data_len);
            return -1;
        }
        *key_data_len -= 8; /* AES-WRAP adds 8 bytes */
        buf = os_malloc(*key_data_len);
        if (buf == NULL) 
        {
            wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
                "WPA: No memory for AES-UNWRAP buffer");
            return -1;
        }
        if (aes_unwrap(sm->ptk.kek, sm->ptk.kek_len, *key_data_len / 8,key_data, buf))
        {
            bin_clear_free(buf, *key_data_len);
            wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
                "WPA: AES unwrap failed - "
                "could not decrypt EAPOL-Key key data");
            return -1;
        }
        os_memcpy(key_data, buf, *key_data_len);
        bin_clear_free(buf, *key_data_len);
        WPA_PUT_BE16(((u8 *) (key + 1)) + mic_len, *key_data_len);
    } 
    else 
    {
        wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
            "WPA: Unsupported key_info type %d", ver);
        return -1;
    }
    wpa_hexdump_key(MSG_DEBUG, "WPA: decrypted EAPOL-Key key data",key_data, *key_data_len);
    return 0;
}


static int wpa_supplicant_verify_eapol_key_mic(struct wpa_sm *sm,
                           struct wpa_eapol_key *key,
                           u16 ver,
                           const u8 *buf, size_t len)
{
    u8 mic[WPA_EAPOL_KEY_MIC_MAX_LEN];
    int ok = 0;
    size_t mic_len = wpa_mic_len(sm->key_mgmt);

    os_memcpy(mic, key + 1, mic_len);
    if (sm->tptk_set) 
    {
        os_memset(key + 1, 0, mic_len);
        wpa_eapol_key_mic(sm->tptk.kck, sm->tptk.kck_len, sm->key_mgmt,
                  ver, buf, len, (u8 *) (key + 1));
        if (os_memcmp_const(mic, key + 1, mic_len) != 0)
        {
            wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
                "WPA: Invalid EAPOL-Key MIC "
                "when using TPTK - ignoring TPTK");
        }
        else
        {
            ok = 1;
            sm->tptk_set = 0;
            sm->ptk_set = 1;
            os_memcpy(&sm->ptk, &sm->tptk, sizeof(sm->ptk));
            os_memset(&sm->tptk, 0, sizeof(sm->tptk));
        }
    }

    if (!ok && sm->ptk_set) 
    {
        os_memset(key + 1, 0, mic_len);
        wpa_eapol_key_mic(sm->ptk.kck, sm->ptk.kck_len, sm->key_mgmt,
                  ver, buf, len, (u8 *) (key + 1));
        if (os_memcmp_const(mic, key + 1, mic_len) != 0) 
        {
            wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
                "WPA: Invalid EAPOL-Key MIC - "
                "dropping packet");
            return -1;
        }
        ok = 1;
    }

    if (!ok) 
    {
        wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
            "WPA: Could not verify EAPOL-Key MIC - "
            "dropping packet");
        return -1;
    }

    os_memcpy(sm->rx_replay_counter, key->replay_counter,
          WPA_REPLAY_COUNTER_LEN);
    sm->rx_replay_counter_set = 1;
    return 0;
}


/**
 * wpa_sm_rx_eapol - Process received WPA EAPOL frames
 * @sm: Pointer to WPA state machine data from wpa_sm_init()
 * @src_addr: Source MAC address of the EAPOL packet
 * @buf: Pointer to the beginning of the EAPOL data (EAPOL header)
 * @len: Length of the EAPOL frame
 * Returns: 1 = WPA EAPOL-Key processed, 0 = not a WPA EAPOL-Key, -1 failure
 *
 * This function is called for each received EAPOL frame. Other than EAPOL-Key
 * frames can be skipped if filtering is done elsewhere. wpa_sm_rx_eapol() is
 * only processing WPA and WPA2 EAPOL-Key frames.
 *
 * The received EAPOL-Key packets are validated and valid packets are replied
 * to. In addition, key material (PTK, GTK) is configured at the end of a
 * successful key handshake.
 */
int wpa_sm_rx_eapol(struct wpa_sm *sm, const u8 *src_addr,
            const u8 *buf, size_t len)
{

    size_t plen, data_len, key_data_len;
    const struct ieee802_1x_hdr *hdr;
    struct wpa_eapol_key *key;
    u16 key_info, ver;
    u8 *tmp = NULL;
    int ret = -1;
    u8 *mic, *key_data;
    size_t mic_len, keyhdrlen;
    printf("%s(%d):\n",__func__,__LINE__);


    mic_len = wpa_mic_len(sm->key_mgmt);
    keyhdrlen = sizeof(*key) + mic_len + 2;
    
    if (len < sizeof(*hdr) + keyhdrlen) 
    {
        printf("WPA: EAPOL frame too short to be a WPA ""EAPOL-Key (len %lu, expecting at least %lu)",
            (unsigned long) len,(unsigned long) sizeof(*hdr) + keyhdrlen);
        return 0;
    }

    hdr = (const struct ieee802_1x_hdr *) buf;
    plen = be_to_host16(hdr->length);
    data_len = plen + sizeof(*hdr);
    printf("%s(%d):version=%d,type=%d,length=%ld\n",__func__,__LINE__,hdr->version, hdr->type,plen);

//  printf("IEEE 802.1X RX: version=%d type=%d length=%lu",hdr->version, hdr->type, (unsigned long) plen);

    if (hdr->version < EAPOL_VERSION) 
    {
        /* TODO: backwards compatibility */
    }
    if (hdr->type != IEEE802_1X_TYPE_EAPOL_KEY) 
    {
        printf("WPA: EAPOL frame (type %u) discarded, ""not a Key frame", hdr->type);
        ret = 0;
        goto out;
    }
    
    wpa_hexdump(MSG_MSGDUMP, "WPA: RX EAPOL-Key", buf, len);
    
    if (plen > len - sizeof(*hdr) || plen < keyhdrlen) 
    {
        printf("WPA: EAPOL frame payload size %lu ""invalid (frame size %lu)",
                                    (unsigned long) plen, (unsigned long) len);
        ret = 0;
        goto out;
    }
    if (data_len < len) 
    {
        printf("WPA: ignoring %lu bytes after the IEEE 802.1X data",
                                    (unsigned long) len - data_len);
    }

    /*
     * Make a copy of the frame since we need to modify the buffer during
     * MAC validation and Key Data decryption.
     */
    tmp = os_malloc(data_len);
    if (tmp == NULL)
        goto out;
    
    os_memcpy(tmp, buf, data_len);
    key = (struct wpa_eapol_key *) (tmp + sizeof(struct ieee802_1x_hdr));
    mic = (u8 *) (key + 1);
    key_data = mic + mic_len + 2;

    if (key->type != EAPOL_KEY_TYPE_WPA && key->type != EAPOL_KEY_TYPE_RSN)
    {
        printf("WPA: EAPOL-Key type (%d) unknown, discarded",key->type);
        ret = 0;
        goto out;
    }

    key_data_len = WPA_GET_BE16(mic + mic_len);
//  wpa_eapol_key_dump(sm, key, key_data_len, mic, mic_len);

    if (key_data_len > plen - keyhdrlen) 
    {
        printf("WPA: Invalid EAPOL-Key frame - key_data overflow (%u > %u)",
                    (unsigned int) key_data_len,(unsigned int) (plen - keyhdrlen));
        goto out;
    }

//  eapol_sm_notify_lower_layer_success(sm->eapol, 0);
    key_info = WPA_GET_BE16(key->key_info);
    ver = key_info & WPA_KEY_INFO_TYPE_MASK;
    if (ver != WPA_KEY_INFO_TYPE_HMAC_MD5_RC4 &&
        ver != WPA_KEY_INFO_TYPE_HMAC_SHA1_AES) 
     {
        printf("WPA: Unsupported EAPOL-Key descriptor version %d",ver);
        goto out;
    }

    if (sm->key_mgmt == WPA_KEY_MGMT_OSEN &&
        ver != WPA_KEY_INFO_TYPE_AKM_DEFINED) 
    {
        printf("OSEN: Unsupported EAPOL-Key descriptor version %d\n",ver);
        goto out;
    }

//  if ((wpa_key_mgmt_suite_b(sm->key_mgmt) ||
//       wpa_key_mgmt_fils(sm->key_mgmt)) &&
//      ver != WPA_KEY_INFO_TYPE_AKM_DEFINED) 
//  {
//      printf("RSN: Unsupported EAPOL-Key descriptor version %d (expected AKM defined = 0)\n",ver);
//      goto out;
//  }

    if (sm->pairwise_cipher == WPA_CIPHER_CCMP &&
        !wpa_key_mgmt_suite_b(sm->key_mgmt) &&
        !wpa_key_mgmt_fils(sm->key_mgmt) &&
        ver != WPA_KEY_INFO_TYPE_HMAC_SHA1_AES) 
    {
        printf("WPA: CCMP is used, but EAPOL-Key descriptor version (%d) is not 2\n", ver);
        if (sm->group_cipher != WPA_CIPHER_CCMP &&
            !(key_info & WPA_KEY_INFO_KEY_TYPE)) 
        {
            /* Earlier versions of IEEE 802.11i did not explicitly
             * require version 2 descriptor for all EAPOL-Key
             * packets, so allow group keys to use version 1 if
             * CCMP is not used for them. */
            printf("WPA: Backwards compatibility: allow invalid version for non-CCMP group keys\n");
        } 
        else if (ver == WPA_KEY_INFO_TYPE_AES_128_CMAC) 
        {
            printf("WPA: Interoperability workaround: allow incorrect (should have been HMAC-SHA1), but stronger (is AES-128-CMAC), descriptor version to be used\n");
        }
        else
            goto out;
    } 
    else if (sm->pairwise_cipher == WPA_CIPHER_GCMP &&
                   !wpa_key_mgmt_suite_b(sm->key_mgmt) &&
            ver != WPA_KEY_INFO_TYPE_HMAC_SHA1_AES) 
    {
        printf("WPA: GCMP is used, but EAPOL-Key descriptor version (%d) is not 2\n", ver);
        goto out;
    }


    if (sm->rx_replay_counter_set &&
        os_memcmp(key->replay_counter, sm->rx_replay_counter,WPA_REPLAY_COUNTER_LEN) <= 0) 
    {
        printf("WPA: EAPOL-Key Replay Counter did not increase - dropping packet\n");
        goto out;
    }

    if (!(key_info & (WPA_KEY_INFO_ACK | WPA_KEY_INFO_SMK_MESSAGE))) 
    {
        printf("WPA: No Ack bit in key_info\n");
        goto out;
    }

    if (key_info & WPA_KEY_INFO_REQUEST) 
    {
        printf("WPA: EAPOL-Key with Request bit - dropped\n");
        goto out;
    }

    if ((key_info & WPA_KEY_INFO_MIC) &&
        wpa_supplicant_verify_eapol_key_mic(sm, key, ver, tmp, data_len))
        goto out;

/*************上半部分完成eapol-key帧的合法性检查*******************/
/*************下班部分执行4次握手******************/
    if ((sm->proto == WPA_PROTO_RSN || sm->proto == WPA_PROTO_OSEN) &&
        (key_info & WPA_KEY_INFO_ENCR_KEY_DATA) && mic_len) 
    {//第三次握手时keydata需要先解密出来才能使用
        if (wpa_supplicant_decrypt_key_data(sm, key, mic_len,
                            ver, key_data,
                            &key_data_len))
            goto out;
    }

    if (key_info & WPA_KEY_INFO_KEY_TYPE) /* 1 = Pairwise, 0 = Group key */
    {
        if (key_info & WPA_KEY_INFO_KEY_INDEX_MASK)
        {
            wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
                "WPA: Ignored EAPOL-Key (Pairwise) with "
                "non-zero key index");
            goto out;
        }
        
        if (key_info & (WPA_KEY_INFO_MIC |WPA_KEY_INFO_ENCR_KEY_DATA)) 
        {
            /* 3/4 4-Way Handshake */
            wpa_supplicant_process_3_of_4(sm, key, ver, key_data,key_data_len);
        }
        else 
        {
            /* 1/4 4-Way Handshake */
            wpa_supplicant_process_1_of_4(sm, src_addr, key,ver, key_data,key_data_len);
        }
    } 
    else if (key_info & WPA_KEY_INFO_SMK_MESSAGE) 
    {
        /* PeerKey SMK Handshake */
        printf("WPA: Unsupported PeerKey SMK Handshake\n");
//      peerkey_rx_eapol_smk(sm, src_addr, key, key_data, key_data_len,
//                   key_info, ver);
    } 
    else 
    {
        printf("WPA: temporary Unsupported 1/2 Group Key Handshake\n");

//      if ((mic_len && (key_info & WPA_KEY_INFO_MIC)) ||
//          (!mic_len && (key_info & WPA_KEY_INFO_ENCR_KEY_DATA))) 
//      {
//          /* 1/2 Group Key Handshake */
//            printf("%s(%d):  1/2 Group Key Handshake\n",__func__,__LINE__);
//          wpa_supplicant_process_1_of_2(sm, src_addr, key,
//                            key_data, key_data_len,ver);
//      } 
//        else
//        {
//          printf("WPA: EAPOL-Key (Group) without Mic/Encr bit - dropped \n");
//      }
    }

    ret = 1;

out:
    bin_clear_free(tmp, data_len);
    return ret;
}

