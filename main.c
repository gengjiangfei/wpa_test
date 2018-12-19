#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()
#include <netdb.h>            // struct addrinfo
#include "common.h"
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/time.h>
#include <sys/select.h>
#include <sys/socket.h>       // needed for socket(
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <errno.h>
#include "defs.h"
#include "l2_packet.h"
#include "wpa_common.h"
#include "wpa.h"
#include "wpa_i.h"
#include "peerkey.h"
#include "crypto/md5.h"
#include "crypto/sha384.h"
#include "crypto/sha1.h"
#include "crypto/sha1_i.h"
#include "utils/includes.h"
//#include "list.h"

struct l2_packet_data 
{
	int fd; /* packet socket for EAPOL frames */
	char ifname[IFNAMSIZ + 1];
	int ifindex;
	u8 own_addr[ETH_ALEN];
	void (*rx_callback)(void *ctx, const u8 *src_addr,
			    const u8 *buf, size_t len);
	void *rx_callback_ctx;
	int l2_hdr; /* whether to include layer 2 (Ethernet) header data
		     * buffers */

};
//typedef struct SHA1Context SHA1_CTX;

#if 0
unsigned int wpa_mic_len(int akmp)
{
	switch (akmp) {
	case WPA_KEY_MGMT_IEEE8021X_SUITE_B_192:
		return 24;
	case WPA_KEY_MGMT_FILS_SHA256:
	case WPA_KEY_MGMT_FILS_SHA384:
	case WPA_KEY_MGMT_FT_FILS_SHA256:
	case WPA_KEY_MGMT_FT_FILS_SHA384:
		return 0;
	default:
		return 16;
	}
}


/**
 * wpa_eapol_key_mic - Calculate EAPOL-Key MIC
 * @key: EAPOL-Key Key Confirmation Key (KCK)
 * @key_len: KCK length in octets
 * @akmp: WPA_KEY_MGMT_* used in key derivation
 * @ver: Key descriptor version (WPA_KEY_INFO_TYPE_*)
 * @buf: Pointer to the beginning of the EAPOL header (version field)
 * @len: Length of the EAPOL frame (from EAPOL header to the end of the frame)
 * @mic: Pointer to the buffer to which the EAPOL-Key MIC is written
 * Returns: 0 on success, -1 on failure
 *
 * Calculate EAPOL-Key MIC for an EAPOL-Key packet. The EAPOL-Key MIC field has
 * to be cleared (all zeroes) when calling this function.
 *
 * Note: 'IEEE Std 802.11i-2004 - 8.5.2 EAPOL-Key frames' has an error in the
 * description of the Key MIC calculation. It includes packet data from the
 * beginning of the EAPOL-Key header, not EAPOL header. This incorrect change
 * happened during final editing of the standard and the correct behavior is
 * defined in the last draft (IEEE 802.11i/D10).
 */
int wpa_eapol_key_mic(const u8 *key, size_t key_len, int akmp, int ver,
		      const u8 *buf, size_t len, u8 *mic)
{
	u8 hash[SHA384_MAC_LEN];

	switch (ver) {
#ifndef CONFIG_FIPS
	case WPA_KEY_INFO_TYPE_HMAC_MD5_RC4:
		return hmac_md5(key, key_len, buf, len, mic);
#endif /* CONFIG_FIPS */
	case WPA_KEY_INFO_TYPE_HMAC_SHA1_AES:
		if (hmac_sha1(key, key_len, buf, len, hash))
			return -1;
		os_memcpy(mic, hash, MD5_MAC_LEN);
		break;
	case WPA_KEY_INFO_TYPE_AKM_DEFINED:
		break;
	default:
		return -1;
	}

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
			printf("WPA: Invalid EAPOL-Key MIC when using TPTK - ignoring TPTK\n");
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
		if (os_memcmp_const(mic, key + 1, mic_len) != 0) {
			printf("WPA: Invalid EAPOL-Key MIC - dropping packet\n");
			return -1;
		}
		ok = 1;
	}

	if (!ok) 
    {
		printf(sm->ctx->msg_ctx, MSG_WARNING,"WPA: Could not verify EAPOL-Key MIC - dropping packet\n");
		return -1;
	}

	os_memcpy(sm->rx_replay_counter, key->replay_counter,WPA_REPLAY_COUNTER_LEN);
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
	struct wpa_peerkey *peerkey = NULL;
	u8 *mic, *key_data;
	size_t mic_len, keyhdrlen;


	mic_len = wpa_mic_len(sm->key_mgmt);
	keyhdrlen = sizeof(*key) + mic_len + 2;

	if (len < sizeof(*hdr) + keyhdrlen) {
		wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
			"WPA: EAPOL frame too short to be a WPA "
			"EAPOL-Key (len %lu, expecting at least %lu)",
			(unsigned long) len,
			(unsigned long) sizeof(*hdr) + keyhdrlen);
		return 0;
	}

	hdr = (const struct ieee802_1x_hdr *) buf;
	plen = be_to_host16(hdr->length);
	data_len = plen + sizeof(*hdr);
	wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
		"IEEE 802.1X RX: version=%d type=%d length=%lu",
		hdr->version, hdr->type, (unsigned long) plen);

	if (hdr->version < EAPOL_VERSION) {
		/* TODO: backwards compatibility */
	}
	if (hdr->type != IEEE802_1X_TYPE_EAPOL_KEY) {
		wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
			"WPA: EAPOL frame (type %u) discarded, "
			"not a Key frame", hdr->type);
		ret = 0;
		goto out;
	}
//	wpa_hexdump(MSG_MSGDUMP, "WPA: RX EAPOL-Key", buf, len);
	if (plen > len - sizeof(*hdr) || plen < keyhdrlen) {
		wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
			"WPA: EAPOL frame payload size %lu "
			"invalid (frame size %lu)",
			(unsigned long) plen, (unsigned long) len);
		ret = 0;
		goto out;
	}
    
	if (data_len < len) 
    {
		wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
			"WPA: ignoring %lu bytes after the IEEE 802.1X data",
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
		wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
			"WPA: EAPOL-Key type (%d) unknown, discarded",
			key->type);
		ret = 0;
		goto out;
	}

	key_data_len = WPA_GET_BE16(mic + mic_len);
//	wpa_eapol_key_dump(sm, key, key_data_len, mic, mic_len);

	if (key_data_len > plen - keyhdrlen) {
		printf("WPA: Invalid EAPOL-Key ""frame - key_data overflow (%u > %u)",
			        (unsigned int) key_data_len,(unsigned int) (plen - keyhdrlen));
		goto out;
	}

//	eapol_sm_notify_lower_layer_success(sm->eapol, 0);
	key_info = WPA_GET_BE16(key->key_info);
	ver = key_info & WPA_KEY_INFO_TYPE_MASK;
	if (ver != WPA_KEY_INFO_TYPE_HMAC_MD5_RC4 &&
	    ver != WPA_KEY_INFO_TYPE_HMAC_SHA1_AES &&
	    !wpa_key_mgmt_suite_b(sm->key_mgmt) &&
	    !wpa_key_mgmt_fils(sm->key_mgmt) &&
	    sm->key_mgmt != WPA_KEY_MGMT_OSEN) 
	{
		printf("WPA: Unsupported EAPOL-Key descriptor version %d",ver);
		goto out;
	}

	if (sm->key_mgmt == WPA_KEY_MGMT_OSEN &&
	    ver != WPA_KEY_INFO_TYPE_AKM_DEFINED) 
	{
		printf("OSEN: Unsupported EAPOL-Key descriptor version %d",ver);
		goto out;
	}

	if ((wpa_key_mgmt_suite_b(sm->key_mgmt) ||
	     wpa_key_mgmt_fils(sm->key_mgmt)) &&
	    ver != WPA_KEY_INFO_TYPE_AKM_DEFINED) 
	{
		printf("RSN: Unsupported EAPOL-Key descriptor version %d (expected AKM defined = 0)",ver);
		goto out;
	}


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



	if (!peerkey && sm->rx_replay_counter_set &&
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

	if (key_info & WPA_KEY_INFO_REQUEST) {
		printf("WPA: EAPOL-Key with Request bit - dropped\n");
		goto out;
	}
    
	if ((key_info & WPA_KEY_INFO_MIC) && !peerkey &&
	    wpa_supplicant_verify_eapol_key_mic(sm, key, ver, tmp, data_len))
		goto out;


	if ((sm->proto == WPA_PROTO_RSN || sm->proto == WPA_PROTO_OSEN) &&
	    (key_info & WPA_KEY_INFO_ENCR_KEY_DATA) && mic_len) 
	{
		if (wpa_supplicant_decrypt_key_data(sm, key, mic_len,
						    ver, key_data,
						    &key_data_len))
			goto out;
	}
#if 0 

	if (key_info & WPA_KEY_INFO_KEY_TYPE) {
		if (key_info & WPA_KEY_INFO_KEY_INDEX_MASK) {
			wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
				"WPA: Ignored EAPOL-Key (Pairwise) with "
				"non-zero key index");
			goto out;
		}
		if (peerkey) {
			/* PeerKey 4-Way Handshake */
			peerkey_rx_eapol_4way(sm, peerkey, key, key_info, ver,
					      key_data, key_data_len);
		} else if (key_info & (WPA_KEY_INFO_MIC |
				       WPA_KEY_INFO_ENCR_KEY_DATA)) {
			/* 3/4 4-Way Handshake */
			wpa_supplicant_process_3_of_4(sm, key, ver, key_data,
						      key_data_len);
		} else {
			/* 1/4 4-Way Handshake */
			wpa_supplicant_process_1_of_4(sm, src_addr, key,
						      ver, key_data,
						      key_data_len);
		}
	} else if (key_info & WPA_KEY_INFO_SMK_MESSAGE) {
		/* PeerKey SMK Handshake */
		peerkey_rx_eapol_smk(sm, src_addr, key, key_data, key_data_len,
				     key_info, ver);
	} else {
		if ((mic_len && (key_info & WPA_KEY_INFO_MIC)) ||
		    (!mic_len && (key_info & WPA_KEY_INFO_ENCR_KEY_DATA))) {
			/* 1/2 Group Key Handshake */
			wpa_supplicant_process_1_of_2(sm, src_addr, key,
						      key_data, key_data_len,
						      ver);
		} else {
			wpa_msg(sm->ctx->msg_ctx, MSG_WARNING,
				"WPA: EAPOL-Key (Group) without Mic/Encr bit - "
				"dropped");
		}
	}
#endif
	ret = 1;

out:
	bin_clear_free(tmp, data_len);
	return ret;
}
#endif
static void driver_atheros_l2_read(void *ctx, const u8 *src_addr, const u8 *buf,size_t len)
{
    struct wpa_sm *wpa = ctx;
    printf("%s(%d):\n",__func__,__LINE__);

    wpa_sm_rx_eapol(wpa, src_addr, buf, len);
}

static void l2_packet_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
    struct l2_packet_data *l2 = eloop_ctx;
    u8 buf[2300];
    int res;
    struct sockaddr_ll ll;
    socklen_t fromlen;

    memset(&ll, 0, sizeof(ll));
    fromlen = sizeof(ll);
    res = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *) &ll,&fromlen);
    if (res < 0) 
    {
        printf("%s(%d) - recvfrom: %s\n",__func__,__LINE__,strerror(errno));
        return;
    }

    printf("%s(%d): src=" MACSTR " len=%d\n",__func__, __LINE__,MAC2STR(ll.sll_addr), (int) res);
    if(l2 != NULL)
        l2->rx_callback(l2->rx_callback_ctx, ll.sll_addr, buf, res);

    return ;
}

struct l2_packet_data * l2_packet_init(
	const char *ifname, const u8 *own_addr, unsigned short protocol,
	void (*rx_callback)(void *ctx, const u8 *src_addr,
			    const u8 *buf, size_t len),
	void *rx_callback_ctx, int l2_hdr)
{
	struct l2_packet_data *l2;
	struct ifreq ifr;
	struct sockaddr_ll ll;
    fd_set fds;
    struct timeval tv;
    
	l2 = os_zalloc(sizeof(struct l2_packet_data));
	if (l2 == NULL)
		return NULL;
    
	os_strlcpy(l2->ifname, ifname, sizeof(l2->ifname));
	l2->rx_callback = rx_callback;
	l2->rx_callback_ctx = rx_callback_ctx;
	l2->l2_hdr = l2_hdr;
#ifndef CONFIG_NO_LINUX_PACKET_SOCKET_WAR
	l2->fd_br_rx = -1;
#endif /* CONFIG_NO_LINUX_PACKET_SOCKET_WAR */

	l2->fd = socket(PF_PACKET, l2_hdr ? SOCK_RAW : SOCK_DGRAM,htons(protocol));
	if (l2->fd < 0) 
    {
		printf("%s: socket(PF_PACKET): %s\n",__func__, strerror(errno));
		os_free(l2);
		return NULL;
	}

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, l2->ifname, sizeof(ifr.ifr_name));

	if (ioctl(l2->fd, SIOCGIFINDEX, &ifr) < 0) 
    {
		printf("%s: ioctl[SIOCGIFINDEX]: %s\n",__func__, strerror(errno));
		close(l2->fd);
		os_free(l2);
		return NULL;
	}

    l2->ifindex = ifr.ifr_ifindex;
	os_memset(&ll, 0, sizeof(ll));
	ll.sll_family = PF_PACKET;
	ll.sll_ifindex = ifr.ifr_ifindex;
	ll.sll_protocol = htons(protocol);

	if (bind(l2->fd, (struct sockaddr *) &ll, sizeof(ll)) < 0) 
    {
		printf("%s: bind[PF_PACKET]: %s\n",__func__, strerror(errno));
		close(l2->fd);
		os_free(l2);
		return NULL;
	}


	if (ioctl(l2->fd, SIOCGIFHWADDR, &ifr) < 0) 
    {
		printf("%s: ioctl[SIOCGIFHWADDR]: %s\n",__func__, strerror(errno));
		close(l2->fd);
		os_free(l2);
		return NULL;
	}

	os_memcpy(l2->own_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    wpa_sm_set_own_addr(l2->rx_callback_ctx,l2->own_addr);

//	eloop_register_read_sock(l2->fd, l2_packet_receive, l2, NULL);
   
     while(1) 
    { 
        FD_ZERO(&fds); //每次循环都要清空集合，否则不能检测描述符变化
        FD_SET(l2->fd,&fds); //添加描述符 
        tv.tv_sec = 1;
        tv.tv_usec = 500;
         switch( select(l2->fd+1,&fds,NULL,NULL,&tv))   //select使用 
         { 
             case -1: 
                {
                    perror ("select");
                    exit(-1);
                    break; //select错误，退出程序 
                }
             case 0:
                {
                    printf("select time out!\n");
                    break; //再次轮询
                }
             default: 
                   if(FD_ISSET(l2->fd,&fds)) //测试sock是否可读，即是否网络上有数据
                   { 
//                         recvfrom(sock,buffer,256,.....);//接受网络数据 
//                         if(FD_ISSET(fp,&fds)) //测试文件是否可写 
//                             fwrite(fp,buffer...);//写入文件 
//                          buffer清空; 
                    printf("%s(%d): recive protocol[%x] ...\n",__func__,__LINE__,htons(protocol));
                    l2_packet_receive(l2->fd,l2,NULL);

                    }// end if break; 
           }// end switch 
      }//end while 

	return l2;



}


#if 0
int wpa_supplicant_init_wpa(struct wpa_supplicant *wpa_s)
{
#ifndef CONFIG_NO_WPA
	struct wpa_sm_ctx *ctx;
	ctx = os_zalloc(sizeof(*ctx));
	if (ctx == NULL) {
		wpa_printf(MSG_ERROR, "Failed to allocate WPA context.");
		return -1;
	}

	ctx->ctx = NULL;
	ctx->msg_ctx = NULL;
	ctx->set_state = NULL;
	ctx->get_state = NULL;
	ctx->deauthenticate = _wpa_supplicant_deauthenticate;
	ctx->set_key = wpa_supplicant_set_key;
	ctx->get_network_ctx = NULL;
	ctx->get_bssid = wpa_supplicant_get_bssid;
	ctx->ether_send = _wpa_ether_send;
	ctx->get_beacon_ie = NULL;
	ctx->alloc_eapol = _wpa_alloc_eapol;
	ctx->cancel_auth_timeout = NULL;
	ctx->add_pmkid = wpa_supplicant_add_pmkid;
	ctx->remove_pmkid = wpa_supplicant_remove_pmkid;

	ctx->mlme_setprotection = wpa_supplicant_mlme_setprotection;


	ctx->set_rekey_offload = wpa_supplicant_set_rekey_offload;
	ctx->key_mgmt_set_pmk = wpa_supplicant_key_mgmt_set_pmk;
	ctx->fils_hlp_rx = wpa_supplicant_fils_hlp_rx;

	
	if (sm_init(ctx) == NULL) {
		wpa_printf(MSG_ERROR, "Failed to initialize WPA state "
			   "machine");
		os_free(ctx);
		return -1;
	}
#endif /* CONFIG_NO_WPA */

	return 0;
}
#endif

/**
 * wpa_sm_init - Initialize WPA state machine
 * @ctx: Context pointer for callbacks; this needs to be an allocated buffer
 * Returns: Pointer to the allocated WPA state machine data
 *
 * This function is used to allocate a new WPA state machine and the returned
 * value is passed to all WPA state machine calls.
 */
struct wpa_sm * sm_init(struct wpa_sm_ctx *ctx)
{
	struct wpa_sm *sm;

	sm = os_zalloc(sizeof(*sm));
	if (sm == NULL)
		return NULL;
	dl_list_init(&sm->pmksa_candidates);
	sm->renew_snonce = 1;
	sm->ctx = ctx;
    
    /***************** add by gjf *******************/
    sm->proto = WPA_PROTO_RSN; 
    sm->key_mgmt = WPA_KEY_MGMT_PSK;
    sm->pairwise_cipher = WPA_CIPHER_CCMP;
    sm->group_cipher = WPA_CIPHER_CCMP;
    memset(sm->rx_replay_counter,0,WPA_REPLAY_COUNTER_LEN);
    /***********************************************/
    
	sm->dot11RSNAConfigPMKLifetime = 43200;
	sm->dot11RSNAConfigPMKReauthThreshold = 70;
	sm->dot11RSNAConfigSATimeout = 60;

	sm->pmksa = (void *) -1;//pmksa_cache_init(wpa_sm_pmksa_free_cb, sm, sm);
	if (sm->pmksa == NULL) {
		wpa_msg(sm->ctx->msg_ctx, MSG_ERROR,
			"RSN: PMKSA cache initialization failed");
		os_free(sm);
		return NULL;
	}
	return sm;
}

int main(int argc,char* argv[])
{

//  l2_packet_init(drv->iface, NULL, ETH_P_EAPOL,handle_read, drv, 1);
    struct wpa_sm *sm;
    char ifname[30]="wlan0";
    if(argv[1] != NULL)
    {
        memset(ifname,0,30);
        strcpy(ifname,argv[1]);
    }

    printf("ifname = %s\n",ifname);
    sm = sm_init(NULL);
    l2_packet_init(ifname, NULL, ETH_P_PAE,driver_atheros_l2_read, sm, 0);
    return 0;
}
