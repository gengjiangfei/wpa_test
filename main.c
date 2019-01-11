#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()
#include <assert.h>
//#include <execinfo.h>
#include <netdb.h>            // struct addrinfo
#include "main.h"
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/time.h>
#include <sys/select.h>
#include <sys/socket.h>       // needed for socket(
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netpacket/packet.h>
//#include <net/if.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/wireless.h>
#include <net/if_arp.h>
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

struct driver_atheros_data {
	void *ctx;
//	struct netlink_data *netlink;
	int ioctl_sock;
	int mlme_sock;
	char ifname[IFNAMSIZ + 1];
	char shared_ifname[IFNAMSIZ];

	int ifindex;
	int ifindex2;
	int if_removed;
    int if_disabled;
	u8 *assoc_req_ies;
	size_t assoc_req_ies_len;
	u8 *assoc_resp_ies;
	size_t assoc_resp_ies_len;
//	struct wpa_driver_capa capa;
	int ignore_scan_done;
	int has_capability;
	int we_version_compiled;

	struct l2_packet_data *l2;

	int operstate;

	char mlmedev[IFNAMSIZ + 1];

	int report_probe_req;
	int last_assoc_mode;
	int assoc_event_sent;
	unsigned int pending_set_chan_freq;
	unsigned int pending_set_chan_dur;
	/* Last IOC_P2P_SET_CHANNEL req_ie */
	unsigned int req_id;
	u8  own_addr[ETH_ALEN];

	int drv_in_scan;
	int drv_in_remain_on_chan;
	enum { ATHR_FULL_SCAN, ATHR_PARTIAL_SCAN } prev_scan_type;

	int start_hostap;

	int country_code;

	int best_24_freq;
	int best_5_freq;
	int best_overall_freq;

	int opmode;
	int disabled;
};

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

struct wpa_ssid 
{
    int id;
    u8 *ssid;//ssid - Service set identifier (network name)
    size_t ssid_len;//ssid_len - Length of the SSID
    char *passphrase;//psk - WPA pre-shared key (256 bits)

    u8 psk[32];//psk - WPA pre-shared key (256 bits)
//    struct dl_list psk_list;//psk_list - Per-client PSKs (struct psk_list_entry)
    int psk_set;//Whether PSK field is configured
    
    int pairwise_cipher;//pairwise_cipher - Bitfield of allowed pairwise ciphers, WPA_CIPHER_*
    int group_cipher;//group_cipher - Bitfield of allowed group ciphers, WPA_CIPHER_*
    int key_mgmt;//key_mgmt - Bitfield of allowed key management protocols WPA_KEY_MGMT_*
    int proto;//proto - Bitfield of allowed protocols, WPA_PROTO_*
    enum wpa_states wpa_state;
};

struct wpa_supplicant 
{
    char ifname[100];
    struct l2_packet_data *l2;
    struct l2_packet_data *l2_br;
//    unsigned char own_addr[ETH_ALEN];
    u8 bssid[ETH_ALEN];
    struct wpa_ssid *current_ssid;
    struct wpa_ssid *last_ssid;
    struct wpa_sm *wpa;
    struct eapol_sm *eapol;
    struct driver_atheros_data *drv_ather;
    unsigned int keys_cleared;/* bitfield of key indexes that the driver is
				    * known not to be configured with a key */
    int mic_errors_seen; /* Michael MIC errors with the current PTK */
    void *drv_priv; /* private data used by driver_ops */
};

#if 0

/*
 * WPA/RSN get/set key request.  Specify the key/cipher
 * type and whether the key is to be used for sending and/or
 * receiving.  The key index should be set only when working
 * with global keys (use IEEE80211_KEYIX_NONE for ``no index'').
 * Otherwise a unicast/pairwise key is specified by the bssid
 * (on a station) or mac address (on an ap).  They key length
 * must include any MIC key data; otherwise it should be no
 more than IEEE80211_KEYBUF_SIZE.
 */
#define __packed		__attribute__((packed))

struct ieee80211req_key {
	u_int8_t	ik_type;	/* key/cipher type */
	u_int8_t	ik_pad;
	u_int16_t	ik_keyix;	/* key index */
	u_int8_t	ik_keylen;	/* key length in bytes */
	u_int8_t	ik_flags;
/* NB: IEEE80211_KEY_XMIT and IEEE80211_KEY_RECV defined elsewhere */
	u_int8_t	ik_macaddr[IEEE80211_ADDR_LEN];
	u_int64_t	ik_keyrsc;	/* key receive sequence counter */
	u_int64_t	ik_keytsc;	/* key transmit sequence counter */
	u_int8_t	ik_keydata[IEEE80211_KEYBUF_SIZE+IEEE80211_MICBUF_SIZE];
}__packed;

struct ieee80211req_del_key {
	u_int8_t	idk_keyix;	/* key index */
	u_int8_t	idk_macaddr[IEEE80211_ADDR_LEN];
};
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


int linux_get_ifhwaddr(int sock, const char *ifname, u8 *addr)
{
	struct ifreq ifr;

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFHWADDR, &ifr)) {
		wpa_printf(MSG_ERROR, "Could not get interface %s hwaddr: %s",
			   ifname, strerror(errno));
		return -1;
	}

	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		wpa_printf(MSG_ERROR, "%s: Invalid HW-addr family 0x%04x",
			   ifname, ifr.ifr_hwaddr.sa_family);
		return -1;
	}

	os_memcpy(addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	return 0;
}

/**
 * driver_atheros_init - Initialize WE driver interface
 * @ctx: context to be used when calling wpa_supplicant functions,
 * e.g., wpa_supplicant_event()
 * @ifname: interface name, e.g., wlan0
 * Returns: Pointer to private data, %NULL on failure
 */
void * driver_atheros_init(const char *ifname)
{
	struct driver_atheros_data *drv;
    

	drv = os_zalloc(sizeof(*drv));
    assert(drv!=NULL);
	os_strlcpy(drv->ifname, ifname, sizeof(drv->ifname));

	drv->ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (drv->ioctl_sock < 0) 
    {
		perror("socket(PF_INET,SOCK_DGRAM)");
		goto err1;
	}

	if (linux_get_ifhwaddr(drv->ioctl_sock, drv->ifname, drv->own_addr) <0)//获取接口MAC地址
		goto err1;


	return drv;

err1:
	os_free(drv);
	return NULL;
}

int driver_atheros_get_bssid(void *priv, u8 *bssid)
{
	struct driver_atheros_data *drv = priv;
	struct iwreq iwr;
	int ret = 0;

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);

	if (ioctl(drv->ioctl_sock, SIOCGIWAP, &iwr) < 0) {
		perror("ioctl[SIOCGIWAP]");
		ret = -1;
	}
	os_memcpy(bssid, iwr.u.ap_addr.sa_data, ETH_ALEN);

	return ret;
}

static inline int wpa_drv_get_bssid(struct wpa_supplicant *wpa_s, u8 *bssid)
{
	return driver_atheros_get_bssid(wpa_s->drv_ather, bssid);
}


static char* athr_get_ioctl_name(int op)
{
	switch (op) {
	case IEEE80211_IOCTL_SETPARAM:
		return "SETPARAM";
	case IEEE80211_IOCTL_GETPARAM:
		return "GETPARAM";
	case IEEE80211_IOCTL_SETKEY:
		return "SETKEY";
	case IEEE80211_IOCTL_SETWMMPARAMS:
		return "SETWMMPARAMS";
	case IEEE80211_IOCTL_DELKEY:
		return "DELKEY";
	case IEEE80211_IOCTL_GETWMMPARAMS:
		return "GETWMMPARAMS";
	case IEEE80211_IOCTL_SETMLME:
		return "SETMLME";
	case IEEE80211_IOCTL_GETCHANINFO:
		return "GETCHANINFO";
	case IEEE80211_IOCTL_SETOPTIE:
		return "SETOPTIE";
	case IEEE80211_IOCTL_GETOPTIE:
		return "GETOPTIE";
	case IEEE80211_IOCTL_ADDMAC:
		return "ADDMAC";
	case IEEE80211_IOCTL_DELMAC:
		return "DELMAC";
	case IEEE80211_IOCTL_GETCHANLIST:
		return "GETCHANLIST";
	case IEEE80211_IOCTL_SETCHANLIST:
		return "SETCHANLIST";
	case IEEE80211_IOCTL_KICKMAC:
		return "KICKMAC";
	case IEEE80211_IOCTL_CHANSWITCH:
		return "CHANSWITCH";
	case IEEE80211_IOCTL_GETMODE:
		return "GETMODE";
	case IEEE80211_IOCTL_SETMODE:
		return "SETMODE";
	case IEEE80211_IOCTL_GET_APPIEBUF:
		return "GET_APPIEBUF";
	case IEEE80211_IOCTL_SET_APPIEBUF:
		return "SET_APPIEBUF";
	case IEEE80211_IOCTL_SET_ACPARAMS:
		return "SET_ACPARAMS";
	case IEEE80211_IOCTL_FILTERFRAME:
		return "FILTERFRAME";
	case IEEE80211_IOCTL_SET_RTPARAMS:
		return "SET_RTPARAMS";
	case IEEE80211_IOCTL_SET_MEDENYENTRY:
		return "SET_MEDENYENTRY";
	case IEEE80211_IOCTL_GET_MACADDR:
		return "GET_MACADDR";
	case IEEE80211_IOCTL_SET_HBRPARAMS:
		return "SET_HBRPARAMS";
	case IEEE80211_IOCTL_SET_RXTIMEOUT:
		return "SET_RXTIMEOUT";
	default:
		return "??";
	}
}

static int set80211priv(struct driver_atheros_data *drv, int op, void *data, int len,int show_err)
{
	struct iwreq iwr;

printf("GJF: %s(%d): len=%d\n",__func__,__LINE__,len);
	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
printf("GJF: %s(%d): IFNAMSIZ=%d\n",__func__,__LINE__,IFNAMSIZ);

	if (len <= IFNAMSIZ) 
    {
		/*
		 * Argument data fits inline; put it there.
		 */
printf("GJF: %s(%d): op=%d, IEEE80211_IOCTL_SET_APPIEBUF=%d\n",__func__,__LINE__,op,IEEE80211_IOCTL_SET_APPIEBUF);
		if (op == IEEE80211_IOCTL_SET_APPIEBUF) 
        {
			wpa_printf(MSG_DEBUG, "%s: APPIEBUF", __func__);
			iwr.u.data.pointer = data;
			iwr.u.data.length = len;
		} 
        else
		    os_memcpy(iwr.u.name, data, len);
	} 
    else 
    {
		/*
		 * Argument data too big for inline transfer; setup a
		 * parameter block instead; the kernel will transfer
		 * the data for the driver.
		 */

		iwr.u.data.pointer = data;
		iwr.u.data.length = len;
printf("GJF: %s(%d): len=%d\n",__func__,__LINE__,iwr.u.data.length);

	}
printf("GJF: %s(%d): ioctl\n",__func__,__LINE__);
wpa_hexdump(MSG_DEBUG, "EAPOL: ioctl set key",iwr.u.data.pointer,iwr.u.data.length);

	if (ioctl(drv->ioctl_sock, op, &iwr) < 0) 
    {
    printf("GJF: %s(%d): show_err=%d\n",__func__,__LINE__,show_err);
		if (show_err) 
        {
			wpa_printf(MSG_DEBUG, "%s: op=%x (%s) len=%d "
				   "name=%s failed: %d (%s)",
				   __func__, op,
				   athr_get_ioctl_name(op),
				   iwr.u.data.length, iwr.u.name,
				   errno, strerror(errno));
		}
		return -1;
	}
printf("GJF: %s(%d):\n",__func__,__LINE__);

	return 0;
}

static const char * athr_get_param_name(int op)
{
	switch (op) 
    {
    	case IEEE80211_IOC_UCASTCIPHERS:
    		return "UCASTCIPHERS";
    	case IEEE80211_IOC_UCASTCIPHER:
    		return "UCASTCIPHER";
    	case IEEE80211_IOC_MCASTCIPHER:
    		return "MCASTCIPHER";
    	default:
    		return "??";
	}
}

/*
 * Function to call a sub-ioctl for setparam.
 * data + 0 = mode = subioctl number
 * data +4 = int parameter.
 */
static int set80211param_ifname(struct driver_atheros_data *drv, const char *ifname,
		     int op, int arg, int show_err)
{
	struct iwreq iwr;

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, ifname, IFNAMSIZ);
	iwr.u.mode = op;
	os_memcpy(iwr.u.name + sizeof(__u32), &arg, sizeof(arg));

	wpa_printf(MSG_DEBUG, "%s: ifname=%s subioctl=%d (%s) arg=%d",
		   __func__, ifname, op, athr_get_param_name(op), arg);
	if (ioctl(drv->ioctl_sock, IEEE80211_IOCTL_SETPARAM, &iwr) < 0) {
		if (show_err)
			wpa_printf(MSG_ERROR, "athr: "
				   "ioctl[IEEE80211_IOCTL_SETPARAM] failed: "
				   "%s", strerror(errno));
		return -1;
	}
	return 0;
}
             
static int set80211param(struct driver_atheros_data *drv, int op, int arg, int show_err)
{
	return set80211param_ifname(drv, drv->ifname, op, arg, show_err);
}

int driver_atheros_alg_to_cipher_suite(int alg, int key_len)
{
        switch (alg) 
        {
            case WPA_ALG_CCMP:
                    return WPA_CIPHER_CCMP;
            case WPA_ALG_TKIP:
                    return WPA_CIPHER_TKIP;
            case WPA_ALG_WEP:
        		if (key_len == 5)
        			return WPA_CIPHER_WEP40;
                else
                     return WPA_CIPHER_WEP104;
            case WPA_ALG_IGTK:
                    return WPA_CIPHER_AES_128_CMAC;
        }
        return WPA_CIPHER_NONE;
}

static int driver_atheros_set_cipher(struct driver_atheros_data *drv, int type,
				     unsigned int suite)
{
	int cipher;

	wpa_printf(MSG_DEBUG, "athr: Set cipher type=%d suite=%d",
		   type, suite);

	switch (suite) {
	case WPA_CIPHER_CCMP:
		cipher = IEEE80211_CIPHER_AES_CCM;
		break;
	case WPA_CIPHER_TKIP:
		cipher = IEEE80211_CIPHER_TKIP;
		break;
	case WPA_CIPHER_WEP104:
	case WPA_CIPHER_WEP40:
		if (type == IEEE80211_IOC_MCASTCIPHER)
			cipher = IEEE80211_CIPHER_WEP;
		else
			return -1;
		break;
	case WPA_CIPHER_NONE:
		cipher = IEEE80211_CIPHER_NONE;
		break;
	default:
		return -1;
	}

	wpa_printf(MSG_DEBUG, "athr: cipher=%d", cipher);

	return set80211param(drv, type, cipher, 1);
}

static int driver_atheros_del_key(struct driver_atheros_data *drv, int key_idx,
		       const u8 *addr)
{
	struct ieee80211req_del_key wk;

	wpa_printf(MSG_DEBUG, "%s: keyidx=%d", __FUNCTION__, key_idx);
	os_memset(&wk, 0, sizeof(wk));
	wk.idk_keyix = key_idx;
	if (addr != NULL)
		os_memcpy(wk.idk_macaddr, addr, IEEE80211_ADDR_LEN);

	return set80211priv(drv, IEEE80211_IOCTL_DELKEY, &wk, sizeof(wk), 1);
}

int driver_atheros_set_key(const char *ifname, void *priv, enum wpa_alg alg,
               const u8 *addr, int key_idx, int set_tx,
               const u8 *seq, size_t seq_len,
               const u8 *key, size_t key_len)
{
	struct driver_atheros_data *drv = priv;
	struct ieee80211req_key k;
	char *alg_name;
	unsigned char cipher;
	if (alg == WPA_ALG_NONE)
		return driver_atheros_del_key(drv, key_idx, addr);

    switch (alg) 
    {
        case WPA_ALG_WEP:
    		alg_name = "WEP";
    		cipher = IEEE80211_CIPHER_WEP;
    		break;
    	case WPA_ALG_TKIP:
    		alg_name = "TKIP";
    		cipher = IEEE80211_CIPHER_TKIP;
    		break;
    	case WPA_ALG_CCMP:
    		alg_name = "CCMP";
    		cipher = IEEE80211_CIPHER_AES_CCM;
    		break;
        default:
    		wpa_printf(MSG_DEBUG, "%s: unknown/unsupported algorithm %d",__FUNCTION__, alg);
    		return -1;
    }

	wpa_printf(MSG_DEBUG, "%s: ifname=%s, alg=%s key_idx=%d set_tx=%d ""seq_len=%lu key_len=%lu",
	 __FUNCTION__, drv->ifname, alg_name, key_idx, set_tx,(unsigned long) seq_len, (unsigned long) key_len);
	if (seq_len > sizeof(u_int64_t)) 
    {
		wpa_printf(MSG_DEBUG, "%s: seq_len %lu too big",
			   __FUNCTION__, (unsigned long) seq_len);
		return -2;
	}
	if (key_len > sizeof(k.ik_keydata)) 
    {
		wpa_printf(MSG_DEBUG, "%s: key length %lu too big",
			   __FUNCTION__, (unsigned long) key_len);
		return -3;
	}
    
	os_memset(&k, 0, sizeof(k));
	k.ik_flags = IEEE80211_KEY_RECV;
	if (set_tx)
		k.ik_flags |= IEEE80211_KEY_XMIT;

	k.ik_type = cipher;

#ifndef IEEE80211_KEY_GROUP
#define IEEE80211_KEY_GROUP 0x04
#endif

	if (addr == NULL)
		wpa_printf(MSG_DEBUG, "athr: addr is NULL");
	else
		wpa_printf(MSG_DEBUG, "athr: addr = " MACSTR, MAC2STR(addr));

    if (addr && !is_broadcast_ether_addr(addr)) 
    {
		if (alg != WPA_ALG_WEP && key_idx && !set_tx) 
        {
			wpa_printf(MSG_DEBUG, "athr: RX GTK: set ""IEEE80211_PARAM_MCASTCIPHER=%d", alg);
			driver_atheros_set_cipher(drv,IEEE80211_PARAM_MCASTCIPHER,driver_atheros_alg_to_cipher_suite(alg,key_len));
			os_memcpy(k.ik_macaddr, addr, IEEE80211_ADDR_LEN);
			wpa_printf(MSG_DEBUG, "athr: addr = " MACSTR,MAC2STR(k.ik_macaddr));
			k.ik_flags |= IEEE80211_KEY_GROUP;
			k.ik_keyix = key_idx;
        }
        else 
        {
			wpa_printf(MSG_DEBUG," set IEEE80211_PARAM_UCASTCIPHER=%d", alg);
			driver_atheros_set_cipher(drv,IEEE80211_PARAM_UCASTCIPHER,driver_atheros_alg_to_cipher_suite(alg, key_len));
			os_memcpy(k.ik_macaddr, addr, IEEE80211_ADDR_LEN);
			wpa_printf(MSG_DEBUG, "addr = " MACSTR,MAC2STR(k.ik_macaddr));
			k.ik_keyix = key_idx == 0 ? IEEE80211_KEYIX_NONE : key_idx;
		}
    }
    else 
    {
		wpa_printf(MSG_DEBUG, "athr: TX GTK: set ""IEEE80211_PARAM_MCASTCIPHER=%d", alg);
		driver_atheros_set_cipher(drv, IEEE80211_PARAM_MCASTCIPHER,driver_atheros_alg_to_cipher_suite(alg, key_len));
		os_memset(k.ik_macaddr, 0xff, IEEE80211_ADDR_LEN);
		wpa_printf(MSG_DEBUG, "athr: addr = " MACSTR,MAC2STR(k.ik_macaddr));
		k.ik_flags |= IEEE80211_KEY_GROUP;
		k.ik_keyix = key_idx;
	}
    
	if (k.ik_keyix != IEEE80211_KEYIX_NONE && set_tx)
		k.ik_flags |= IEEE80211_KEY_DEFAULT;
    
	k.ik_keylen = key_len;
	if (seq) 
    {
#ifdef WORDS_BIGENDIAN
		/*
		 * k.ik_keyrsc is in host byte order (big endian), need to
		 * swap it to match with the byte order used in WPA.
		 */
		int i;
		u8 *keyrsc = (u8 *) &k.ik_keyrsc;
		for (i = 0; i < seq_len; i++)
			keyrsc[WPA_KEY_RSC_LEN - i - 1] = seq[i];
#else /* WORDS_BIGENDIAN */
		os_memcpy(&k.ik_keyrsc, seq, seq_len);
#endif /* WORDS_BIGENDIAN */
	}
	os_memcpy(k.ik_keydata, key, key_len);
#define S(a) (sizeof(a))
//printf("GJF: %s(%d): size_k=%d,key_len=%d,IEEE80211_KEYBUF_SIZE=%d,IEEE80211_MICBUF_SIZE=%d,IEEE80211_ADDR_LEN=%d\n",__func__,__LINE__,sizeof(k),key_len,IEEE80211_KEYBUF_SIZE,IEEE80211_MICBUF_SIZE,IEEE80211_ADDR_LEN);
printf("GJF: %s(%d): %d,%d,%d,%d,%d,%d,%d\n",__func__,__LINE__,S(k.ik_flags),S(k.ik_keyix),
        S(k.ik_keylen),S(k.ik_keyrsc),S(k.ik_keytsc),S(k.ik_pad),S(k.ik_type));
printf("GJF: %s(%d): %d,%d,size_k=%d\n",__func__,__LINE__,S(k.ik_macaddr),S(k.ik_keydata),sizeof(k));
	return set80211priv(drv, IEEE80211_IOCTL_SETKEY, &k, sizeof(k), 1);

}
static int wpa_supplicant_set_key(void *_wpa_s, enum wpa_alg alg,
				  const u8 *addr, int key_idx, int set_tx,
				  const u8 *seq, size_t seq_len,
				  const u8 *key, size_t key_len)
{
	struct wpa_supplicant *wpa_s = _wpa_s;
	if (alg == WPA_ALG_TKIP && key_idx == 0 && key_len == 32) {
		/* Clear the MIC error counter when setting a new PTK. */
		wpa_s->mic_errors_seen = 0;
	}
	return driver_atheros_set_key(wpa_s->ifname,wpa_s->drv_ather,
					      alg, addr, key_idx, set_tx,
					      seq, seq_len, key, key_len);
}
struct l2_packet_data * l2_packet_init(
	const char *ifname, const u8 *own_addr, unsigned short protocol,
	void (*rx_callback)(void *ctx, const u8 *src_addr,const u8 *buf, size_t len),
	void *rx_callback_ctx, int l2_hdr)
{
	struct l2_packet_data *l2;
	struct ifreq ifr;
	struct sockaddr_ll ll;
    
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
    printf("%s(%d): own_addr="MACSTR"\n",__func__,__LINE__,MAC2STR(l2->own_addr));
//	eloop_register_read_sock(l2->fd, l2_packet_receive, l2, NULL);

	return l2;

}
struct wpa_ssid * ssid_init(void)
{
	struct wpa_ssid *apinfo;

	apinfo = os_zalloc(sizeof(*apinfo));
    assert(apinfo != NULL);

    apinfo->id = 0;
    apinfo->ssid = "CMCC-abc888_wpa";
    apinfo->ssid_len = strlen(apinfo->ssid);
    apinfo->passphrase = "87654321";
    apinfo->key_mgmt = WPA_KEY_MGMT_PSK;
    apinfo->pairwise_cipher = WPA_CIPHER_CCMP;// | WPA_CIPHER_TKIP;
    apinfo->group_cipher = WPA_CIPHER_TKIP; //| WPA_CIPHER_TKIP;
    apinfo->proto = WPA_PROTO_RSN;// | WPA_PROTO_WPA;
    memset(apinfo->psk,0,PMK_LEN);
    apinfo->psk_set = 0;

    return apinfo;

}

static u8 * wpa_alloc_eapol(const struct wpa_supplicant *wpa_s, u8 type,
			    const void *data, u16 data_len,
			    size_t *msg_len, void **data_pos)
{
	struct ieee802_1x_hdr *hdr;

	*msg_len = sizeof(*hdr) + data_len;
	hdr = os_malloc(*msg_len);
	if (hdr == NULL)
		return NULL;

	hdr->version = EAPOL_VERSION; //wpa_s->conf->eapol_version;
	hdr->type = type;
	hdr->length = host_to_be16(data_len);

	if (data)
		os_memcpy(hdr + 1, data, data_len);
	else
		os_memset(hdr + 1, 0, data_len);

	if (data_pos)
		*data_pos = hdr + 1;

	return (u8 *) hdr;
}



int l2_packet_send(struct l2_packet_data *l2, const u8 *dst_addr, u16 proto,
		   const u8 *buf, size_t len)
{
	int ret;
	if (l2 == NULL)
		return -1;
	if (l2->l2_hdr) {
		ret = send(l2->fd, buf, len, 0);
		if (ret < 0)
			wpa_printf(MSG_ERROR, "l2_packet_send - send: %s",
				   strerror(errno));
	} else {
		struct sockaddr_ll ll;
		os_memset(&ll, 0, sizeof(ll));
		ll.sll_family = AF_PACKET;
		ll.sll_ifindex = l2->ifindex;
		ll.sll_protocol = htons(proto);
		ll.sll_halen = ETH_ALEN;
		os_memcpy(ll.sll_addr, dst_addr, ETH_ALEN);
		ret = sendto(l2->fd, buf, len, 0, (struct sockaddr *) &ll,
			     sizeof(ll));
		if (ret < 0) {
			wpa_printf(MSG_ERROR, "l2_packet_send - sendto: %s",
				   strerror(errno));
		}
	}
	return ret;
}

/**
 * wpa_ether_send - Send Ethernet frame
 * @wpa_s: Pointer to wpa_supplicant data
 * @dest: Destination MAC address
 * @proto: Ethertype in host byte order
 * @buf: Frame payload starting from IEEE 802.1X header
 * @len: Frame payload length
 * Returns: >=0 on success, <0 on failure
 */
static int wpa_ether_send(struct wpa_supplicant *wpa_s, const u8 *dest,
			  u16 proto, const u8 *buf, size_t len)
{
#ifdef CONFIG_TESTING_OPTIONS
	if (wpa_s->ext_eapol_frame_io && proto == ETH_P_EAPOL) {
		size_t hex_len = 2 * len + 1;
		char *hex = os_malloc(hex_len);

		if (hex == NULL)
			return -1;
		wpa_snprintf_hex(hex, hex_len, buf, len);
		wpa_msg(wpa_s, MSG_INFO, "EAPOL-TX " MACSTR " %s",
			MAC2STR(dest), hex);
		os_free(hex);
		return 0;
	}
#endif /* CONFIG_TESTING_OPTIONS */

	if (wpa_s->l2) {
		return l2_packet_send(wpa_s->l2, dest, proto, buf, len);
	}

	return -1;
}

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
    assert(ctx != NULL);
    
	struct wpa_sm *sm=NULL;
    struct wpa_ssid *apinfo=NULL;
    struct wpa_supplicant *wpa_s;
    
	sm = os_zalloc(sizeof(*sm));
	if (sm == NULL)
		return NULL;
	dl_list_init(&sm->pmksa_candidates);
	sm->renew_snonce = 1;
	sm->ctx = ctx;

    
    /***************** add by gjf *******************/
    wpa_s = (struct wpa_supplicant *)(ctx->ctx);
    apinfo = wpa_s->current_ssid;
    
    if(apinfo == NULL)
    {
        sm->proto = WPA_PROTO_RSN; 
        sm->key_mgmt = WPA_KEY_MGMT_PSK;
        sm->pairwise_cipher = WPA_CIPHER_CCMP;
        sm->group_cipher = WPA_CIPHER_TKIP;
        memset(sm->rx_replay_counter,0,WPA_REPLAY_COUNTER_LEN);
    }
    else
    {
        strncpy(sm->ssid,apinfo->ssid,apinfo->ssid_len);
        sm->ssid_len = apinfo->ssid_len;
        sm->key_mgmt = apinfo->key_mgmt;
        sm->pairwise_cipher = apinfo->pairwise_cipher;
        sm->group_cipher = apinfo->group_cipher;
        sm->proto = apinfo->proto;
        memcpy(sm->pmk,apinfo->psk,PMK_LEN);
        sm->pmk_len = PMK_LEN;
    }
    //driver_atheros_get_bssid(wpa_s->drv_ather,sm->bssid);
//    printf("%s(%d): Get BSSID="MACSTR"\n",__func__,__LINE__,MAC2STR(sm->bssid));
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

void sm_deinit(struct wpa_sm *sm)
{
    return ;
}

int wpa_supplicant_init_wpa(struct wpa_supplicant *wpa_s)
{
	struct wpa_sm_ctx *ctx;
	ctx = os_zalloc(sizeof(*ctx));
	if (ctx == NULL) {
		wpa_printf(MSG_ERROR, "Failed to allocate WPA context.");
		return -1;
	}

	ctx->ctx = wpa_s;
	ctx->msg_ctx = wpa_s;
	ctx->ether_send = wpa_ether_send;
	ctx->alloc_eapol = wpa_alloc_eapol;
    ctx->get_bssid = wpa_drv_get_bssid;
    ctx->set_key = wpa_supplicant_set_key;
    wpa_s->wpa = sm_init(ctx);
	return 0;
}

void set_rsn_ie(struct wpa_sm *sm)
{
    u8 wpa_ie[80];
    size_t wpa_ie_len = sizeof(wpa_ie);
    wpa_sm_set_assoc_wpa_ie_default(sm,wpa_ie,&wpa_ie_len);

}

int main(int argc,char* argv[])
{

    struct wpa_sm *sm=NULL;
//    struct wpa_ssid *ssid=NULL;
//    struct driver_atheros_data *drv_ather = NULL;
    struct wpa_supplicant wpa_s;
    struct l2_packet_data *l2;
    fd_set fds;
    struct timeval tv;

    wpa_debug_level = MSG_EXCESSIVE;
    char ifname[30]="ath8";
    if(argv[1] != NULL)
    {
        memset(ifname,0,30);
        if(sizeof(argv[1]) >= 30)
            printf("fail: ifname too long\n");
        else
            strcpy(ifname,argv[1]);
    }

    printf("ifname = %s\n",ifname);

    wpa_s.drv_ather = driver_atheros_init(ifname);
    if(wpa_s.drv_ather == NULL)
    {
        printf("%s(%d): driver atheros init failuer!\n",__func__,__LINE__);
        return 0;
    }
    wpa_s.current_ssid = ssid_init();
    
    printf("gjf==> %s(%d):\n ssid=%s\n ssid_len=%ld\n passphrase=%s\n "
           "pairwise_cipher=%d\n group_cipher=%d\n key_mgmt=%d\n proto=%d\n",
        __func__,__LINE__,wpa_s.current_ssid->ssid,wpa_s.current_ssid->ssid_len,wpa_s.current_ssid->passphrase,
            wpa_s.current_ssid->pairwise_cipher,wpa_s.current_ssid->group_cipher,wpa_s.current_ssid->key_mgmt,wpa_s.current_ssid->proto);
    
    /*生成PMK*/
    pbkdf2_sha1(wpa_s.current_ssid->passphrase, wpa_s.current_ssid->ssid, wpa_s.current_ssid->ssid_len, 4096,wpa_s.current_ssid->psk, PMK_LEN);
    wpa_hexdump(MSG_ERROR, "WPA: Generate PMK",wpa_s.current_ssid->psk,PMK_LEN);
    
    wpa_supplicant_init_wpa(&wpa_s);
    sm = wpa_s.wpa;

    set_rsn_ie(sm);

    wpa_hexdump(MSG_ERROR, "WPA: Generate RSN IE",sm->assoc_wpa_ie,sm->assoc_wpa_ie_len);
    l2 = l2_packet_init(ifname,NULL, ETH_P_PAE,driver_atheros_l2_read, sm, 0);
    wpa_s.l2 = l2;

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
//                    printf("select time out!\n");
                    break; //再次轮询
                }
             default: 
                   if(FD_ISSET(l2->fd,&fds)) //测试sock是否可读，即是否网络上有数据
                   { 
                        printf("%s(%d): recive protocol[%x] ...\n",__func__,__LINE__,ETH_P_PAE);
                        l2_packet_receive(l2->fd,l2,NULL);

                    }// end if break; 
           }// end switch 
      }//end while 

    return 0;
}
