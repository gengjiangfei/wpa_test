#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()
#include <assert.h>
#include <netdb.h>            // struct addrinfo
#include "main.h"
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/time.h>
#include <sys/select.h>
#include <sys/socket.h>       // needed for socket(
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netpacket/packet.h>
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

struct driver_atheros_data 
{
    void *ctx;
    int ioctl_sock;
//    int mlme_sock;
    char ifname[IFNAMSIZ + 1];
//    char shared_ifname[IFNAMSIZ];
    struct l2_packet_data *l2;
//    int operstate;
//    int report_probe_req;
    u8  own_addr[ETH_ALEN];
    int opmode;
    int disabled;
};

struct l2_packet_data 
{
    int fd; /* packet socket for EAPOL frames */
    char ifname[IFNAMSIZ + 1];
    int ifindex;
    u8 own_addr[ETH_ALEN];
    void (*rx_callback)(void *ctx, const u8 *src_addr,const u8 *buf, size_t len);
    void *rx_callback_ctx;
    int l2_hdr; /* whether to include layer 2 (Ethernet) header data buffers */
};

struct wpa_ssid 
{
    int id;
    u8 *ssid;//ssid - Service set identifier (network name)
    size_t ssid_len;//ssid_len - Length of the SSID
    char *passphrase;//psk - WPA pre-shared key (256 bits)

    u8 psk[32];//psk - WPA pre-shared key (256 bits)
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
    enum wpa_states wpa_state;
};

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
    if (ioctl(sock, SIOCGIFHWADDR, &ifr)) 
    {
        wpa_printf(MSG_ERROR, "Could not get interface %s hwaddr: %s",ifname, strerror(errno));
        return -1;
    }

    if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
    {
        wpa_printf(MSG_ERROR, "%s: Invalid HW-addr family 0x%04x",ifname, ifr.ifr_hwaddr.sa_family);
        return -1;
    }

    os_memcpy(addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    return 0;
}

/*创建atheros驱动通信的ioctl接口*/
void * driver_atheros_init(const char *ifname)
{
    struct driver_atheros_data *drv;
    

    drv = os_zalloc(sizeof(*drv));
//    if(drv!=NULL)
//        return NULL;
    ASSERT(drv!=NULL);
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

static inline int wpa_drv_get_bssid(void *ctx, u8 *bssid)
{
    struct wpa_supplicant *wpa_s = ctx;

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
    return driver_atheros_set_key(wpa_s->ifname,wpa_s->drv_ather,
                          alg, addr, key_idx, set_tx,
                          seq, seq_len, key, key_len);
}

static int
driver_atheros_set_mlme(struct driver_atheros_data *drv, int op,
			const u8 *bssid, const u8 *ssid)
{
	struct ieee80211req_mlme mlme;
	int ret = 0;

	os_memset(&mlme, 0, sizeof(mlme));
	mlme.im_op = op;
	if (bssid)
    {
		os_memcpy(mlme.im_macaddr, bssid, IEEE80211_ADDR_LEN);
		wpa_printf(MSG_DEBUG, "Associating.. AP BSSID=" MACSTR ", "
			   "ssid=%s, op=%d",MAC2STR(bssid), ssid, op);
	}

	wpa_printf(MSG_DEBUG, " %s: OP mode = %d", __func__, op);

	if (set80211priv(drv, IEEE80211_IOCTL_SETMLME, &mlme,sizeof(mlme), 1) < 0)
    {
		wpa_printf(MSG_DEBUG, "%s: SETMLME[ASSOC] failed", __func__);
		ret = -1;
	}

	return ret;
}

/**
 * driver_atheros_set_bssid - Set BSSID, SIOCSIWAP
 * @priv: Pointer to private wext data from driver_atheros_init()
 * @bssid: BSSID
 * Returns: 0 on success, -1 on failure
 */
int driver_atheros_set_bssid(void *priv, const u8 *bssid)
{
	struct driver_atheros_data *drv = priv;
	struct iwreq iwr;
	int ret = 0;

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
	iwr.u.ap_addr.sa_family = ARPHRD_ETHER;
	if (bssid)
		os_memcpy(iwr.u.ap_addr.sa_data, bssid, ETH_ALEN);
	else
		os_memset(iwr.u.ap_addr.sa_data, 0, ETH_ALEN);

	if (ioctl(drv->ioctl_sock, SIOCSIWAP, &iwr) < 0) {
		perror("ioctl[SIOCSIWAP]");
		ret = -1;
	}

	return ret;
}

static void athr_clear_bssid(struct driver_atheros_data *drv)
{
	struct iwreq iwr;
	const u8 null_bssid[ETH_ALEN] = { 0, 0, 0, 0, 0, 0 };

	/*
	 * Avoid trigger that the driver could consider as a request for a new
	 * IBSS to be formed.
	 */
	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
	if (ioctl(drv->ioctl_sock, SIOCGIWMODE, &iwr) < 0)
    {
		perror("ioctl[SIOCGIWMODE]");
		iwr.u.mode = IW_MODE_INFRA;
	}

	if (iwr.u.mode == IW_MODE_INFRA)
    {
		/* Clear the BSSID selection */
		if (driver_atheros_set_bssid(drv, null_bssid) < 0)
			wpa_printf(MSG_DEBUG, "athr: Failed to clear BSSID");
	}
}

static inline int wpa_drv_deauthenticate(struct wpa_supplicant *wpa_s,
					 const u8 *addr, int reason_code)
{
	int ret;
	wpa_printf(MSG_DEBUG, "%s", __FUNCTION__);
	ret = driver_atheros_set_mlme(wpa_s->drv_ather, IEEE80211_MLME_DEAUTH, NULL, NULL);
	athr_clear_bssid(wpa_s->drv_ather);
	return ret;
}

void wpa_supplicant_deauthenticate(void *ctx,int reason_code)
{
	u8 *addr = NULL;
    struct wpa_supplicant *wpa_s = ctx;
//	wpa_dbg(wpa_s, MSG_DEBUG, "Request to deauthenticate - bssid=" MACSTR
//		" pending_bssid=" MACSTR " reason=%d state=%s",
//		MAC2STR(wpa_s->bssid), MAC2STR(wpa_s->pending_bssid),
//		reason_code, wpa_supplicant_state_txt(wpa_s->wpa_state));
    
    addr = wpa_s->bssid;
	if (addr)
    {
		wpa_drv_deauthenticate(wpa_s, addr, reason_code);
	}

//	wpa_supplicant_clear_connection(wpa_s, addr);
}

void wpa_supplicant_set_state(void *ctx,enum wpa_states state)
{
    struct wpa_supplicant *wpa_s = ctx;
	wpa_s->wpa_state = state;//改变当前的状态
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
//  eloop_register_read_sock(l2->fd, l2_packet_receive, l2, NULL);

    return l2;

}

static int newline_terminated(const char *buf, size_t buflen)
{
	size_t len = os_strlen(buf);
	if (len == 0)
		return 0;
	if (len == buflen - 1 && buf[buflen - 1] != '\r' &&
	    buf[len - 1] != '\n')
		return 0;
	return 1;
}
static void skip_line_end(FILE *stream)
{
	char buf[100];
	while (fgets(buf, sizeof(buf), stream))
    {
		buf[sizeof(buf) - 1] = '\0';
		if (newline_terminated(buf, sizeof(buf)))
			return;
	}
}
/**
 * wpa_config_get_line - Read the next configuration file line
 * @s: Buffer for the line
 * @size: The buffer length
 * @stream: File stream to read from
 * @line: Pointer to a variable storing the file line number
 * @_pos: Buffer for the pointer to the beginning of data on the text line or
 * %NULL if not needed (returned value used instead)
 * Returns: Pointer to the beginning of data on the text line or %NULL if no
 * more text lines are available.
 *
 * This function reads the next non-empty line from the configuration file and
 * removes comments. The returned string is guaranteed to be null-terminated.
 */
static char * wpa_config_get_line(char *s, int size, FILE *stream, int *line,
				  char **_pos)
{
	char *pos, *end, *sstart;

	while (fgets(s, size, stream)) {
		(*line)++;
		s[size - 1] = '\0';
		if (!newline_terminated(s, size)) {
			/*
			 * The line was truncated - skip rest of it to avoid
			 * confusing error messages.
			 */
			wpa_printf(MSG_INFO, "Long line in configuration file "
				   "truncated");
			skip_line_end(stream);
		}
		pos = s;

		/* Skip white space from the beginning of line. */
		while (*pos == ' ' || *pos == '\t' || *pos == '\r')
			pos++;

		/* Skip comment lines and empty lines */
		if (*pos == '#' || *pos == '\n' || *pos == '\0')
			continue;

		/*
		 * Remove # comments unless they are within a double quoted
		 * string.
		 */
		sstart = os_strchr(pos, '"');
		if (sstart)
			sstart = os_strrchr(sstart + 1, '"');
		if (!sstart)
			sstart = pos;
		end = os_strchr(sstart, '#');
		if (end)
			*end-- = '\0';
		else
			end = pos + os_strlen(pos) - 1;

		/* Remove trailing white space. */
		while (end > pos &&
		       (*end == '\n' || *end == ' ' || *end == '\t' ||
			*end == '\r'))
			*end-- = '\0';

		if (*pos == '\0')
			continue;

		if (_pos)
			*_pos = pos;
		return pos;
	}

	if (_pos)
		*_pos = NULL;
	return NULL;
}

int has_ctrl_char(const u8 *data, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
    {
		if (data[i] < 32 || data[i] == 127)
			return 1;
	}
	return 0;
}

void str_clear_free(char *str)
{
	if (str)
    {
		size_t len = os_strlen(str);
		os_memset(str, 0, len);
		os_free(str);
	}
}

char * dup_binstr(const void *src, size_t len)
{
	char *res;

	if (src == NULL)
		return NULL;
	res = os_malloc(len + 1);
	if (res == NULL)
		return NULL;
	os_memcpy(res, src, len);
	res[len] = '\0';

	return res;
}

/**
-1  失败
0  成功
1  密码未改变
**/
static int wpa_config_parse_psk(struct wpa_ssid *ssid, int line,const char *value)
{
	if (*value == '"') 
    {
		const char *pos;
		size_t len;

		value++;
		pos = os_strrchr(value, '"');
		if (pos)
			len = pos - value;
		else
			len = os_strlen(value);
		if (len < 8 || len > 63) 
        {
			wpa_printf(MSG_ERROR, "Line %d: Invalid passphrase "
				   "length %lu (expected: 8..63) '%s'.",
				   line, (unsigned long) len, value);
			return -1;
		}
		wpa_hexdump_ascii_key(MSG_MSGDUMP, "PSK (ASCII passphrase)",(u8 *) value, len);
		if (has_ctrl_char((u8 *) value, len))
        {
			wpa_printf(MSG_ERROR,
				   "Line %d: Invalid passphrase character",
				   line);
			return -1;
		}
		if (ssid->passphrase && os_strlen(ssid->passphrase) == len &&
		    os_memcmp(ssid->passphrase, value, len) == 0) 
		{
			/* No change to the previously configured value */
			return 1;
		}
		ssid->psk_set = 0;
		str_clear_free(ssid->passphrase);
		ssid->passphrase = dup_binstr(value, len);
		if (ssid->passphrase == NULL)
			return -1;
        
		return 0;
	}

	return -1;
}


static int wpa_config_parse_key_mgmt(struct wpa_ssid *ssid, int line,const char *value)
{
	int val = 0, last, errors = 0;
	char *start, *end, *buf;

	buf = os_strdup(value);
	if (buf == NULL)
		return -1;
	start = buf;

	while (*start != '\0')
    {
		while (*start == ' ' || *start == '\t')
			start++;
		if (*start == '\0')
			break;
		end = start;
		while (*end != ' ' && *end != '\t' && *end != '\0')
			end++;
		last = *end == '\0';
		*end = '\0';
		if (os_strcmp(start, "WPA-PSK") == 0)
			val |= WPA_KEY_MGMT_PSK;
		else if (os_strcmp(start, "WPA-EAP") == 0)
			val |= WPA_KEY_MGMT_IEEE8021X;
		else if (os_strcmp(start, "IEEE8021X") == 0)
			val |= WPA_KEY_MGMT_IEEE8021X_NO_WPA;
		else if (os_strcmp(start, "NONE") == 0)
			val |= WPA_KEY_MGMT_NONE;
		else if (os_strcmp(start, "WPA-NONE") == 0)
			val |= WPA_KEY_MGMT_WPA_NONE;
		else {
			wpa_printf(MSG_ERROR, "Line %d: invalid key_mgmt '%s'",
				   line, start);
			errors++;
		}

		if (last)
			break;
		start = end + 1;
	}
	os_free(buf);

	if (val == 0)
    {
		wpa_printf(MSG_ERROR,"Line %d: no key_mgmt values configured.", line);
		errors++;
	}

	if (!errors && ssid->key_mgmt == val)
		return 1;
	wpa_printf(MSG_MSGDUMP, "key_mgmt: 0x%x", val);
	ssid->key_mgmt = val;
	return errors ? -1 : 0;
}

static int wpa_config_parse_proto(struct wpa_ssid *ssid, int line,const char *value)
{
	int val = 0, last, errors = 0;
	char *start, *end, *buf;

	buf = os_strdup(value);
	if (buf == NULL)
		return -1;
	start = buf;

	while (*start != '\0')
    {
		while (*start == ' ' || *start == '\t')
			start++;
		if (*start == '\0')
			break;
		end = start;
		while (*end != ' ' && *end != '\t' && *end != '\0')
			end++;
		last = *end == '\0';
		*end = '\0';
		if (os_strcmp(start, "WPA") == 0)
			val |= WPA_PROTO_WPA;
		else if (os_strcmp(start, "RSN") == 0 ||
			 os_strcmp(start, "WPA2") == 0)
			val |= WPA_PROTO_RSN;
		else if (os_strcmp(start, "OSEN") == 0)
			val |= WPA_PROTO_OSEN;
		else {
			wpa_printf(MSG_ERROR, "Line %d: invalid proto '%s'",
				   line, start);
			errors++;
		}

		if (last)
			break;
		start = end + 1;
	}
	os_free(buf);

	if (val == 0)
    {
		wpa_printf(MSG_ERROR,
			   "Line %d: no proto values configured.", line);
		errors++;
	}

	if (!errors && ssid->proto == val)
		return 1;
	wpa_printf(MSG_MSGDUMP, "proto: 0x%x", val);
	ssid->proto = val;
	return errors ? -1 : 0;
}

int wpa_parse_cipher(const char *value)
{
	int val = 0, last;
	char *start, *end, *buf;

	buf = os_strdup(value);
	if (buf == NULL)
		return -1;
	start = buf;

	while (*start != '\0')
    {
		while (*start == ' ' || *start == '\t')
			start++;
		if (*start == '\0')
			break;
		end = start;
		while (*end != ' ' && *end != '\t' && *end != '\0')
			end++;
		last = *end == '\0';
		*end = '\0';
		if (os_strcmp(start, "CCMP-256") == 0)
			val |= WPA_CIPHER_CCMP_256;
		else if (os_strcmp(start, "GCMP-256") == 0)
			val |= WPA_CIPHER_GCMP_256;
		else if (os_strcmp(start, "CCMP") == 0)
			val |= WPA_CIPHER_CCMP;
		else if (os_strcmp(start, "GCMP") == 0)
			val |= WPA_CIPHER_GCMP;
		else if (os_strcmp(start, "TKIP") == 0)
			val |= WPA_CIPHER_TKIP;
		else if (os_strcmp(start, "WEP104") == 0)
			val |= WPA_CIPHER_WEP104;
		else if (os_strcmp(start, "WEP40") == 0)
			val |= WPA_CIPHER_WEP40;
		else if (os_strcmp(start, "NONE") == 0)
			val |= WPA_CIPHER_NONE;
		else if (os_strcmp(start, "GTK_NOT_USED") == 0)
			val |= WPA_CIPHER_GTK_NOT_USED;
		else {
			os_free(buf);
			return -1;
		}

		if (last)
			break;
		start = end + 1;
	}
	os_free(buf);

	return val;
}

static int wpa_config_parse_cipher(int line, const char *value)
{

	int val = wpa_parse_cipher(value);
	if (val < 0) {
		wpa_printf(MSG_ERROR, "Line %d: invalid cipher '%s'.",
			   line, value);
		return -1;
	}
	if (val == 0) {
		wpa_printf(MSG_ERROR, "Line %d: no cipher values configured.",
			   line);
		return -1;
	}
	return val;
}

static int wpa_config_parse_pairwise(struct wpa_ssid *ssid, int line,const char *value)
{
	int val;
	val = wpa_config_parse_cipher(line, value);
	if (val == -1)
		return -1;
	if (val & ~WPA_ALLOWED_PAIRWISE_CIPHERS) {
		wpa_printf(MSG_ERROR, "Line %d: not allowed pairwise cipher "
			   "(0x%x).", line, val);
		return -1;
	}

	if (ssid->pairwise_cipher == val)
		return 1;
	wpa_printf(MSG_MSGDUMP, "pairwise: 0x%x", val);
	ssid->pairwise_cipher = val;
	return 0;
}
static int wpa_config_parse_group(struct wpa_ssid *ssid, int line,const char *value)
{
	int val;
	val = wpa_config_parse_cipher(line, value);
	if (val == -1)
		return -1;

	/*
	 * Backwards compatibility - filter out WEP ciphers that were previously
	 * allowed.
	 */
	val &= ~(WPA_CIPHER_WEP104 | WPA_CIPHER_WEP40);

	if (val & ~WPA_ALLOWED_GROUP_CIPHERS) {
		wpa_printf(MSG_ERROR, "Line %d: not allowed group cipher "
			   "(0x%x).", line, val);
		return -1;
	}

	if (ssid->group_cipher == val)
		return 1;
	wpa_printf(MSG_MSGDUMP, "group: 0x%x", val);
	ssid->group_cipher = val;
	return 0;
}
struct wpa_ssid * wpa_config_read(const char *name)
{
	FILE *f;
	char buf[512], *pos,*pos2;
    struct wpa_ssid *apinfo;
    int sval_len=0;
    int line=0;
    
    apinfo = os_zalloc(sizeof(*apinfo));
    ASSERT(apinfo != NULL);

	f = fopen(name, "r");
	if (f == NULL)
    {
		wpa_printf(MSG_ERROR, "Failed to open config file '%s',error: %s", name, strerror(errno));
		os_free(apinfo);
		return NULL;
	}
	while (wpa_config_get_line(buf, sizeof(buf), f, &line, &pos))
    {
       pos2 = os_strchr(pos,'=');
       if(pos2 == NULL)
       {
    		wpa_printf(MSG_ERROR, "Line %d: Invalid param '%s'.", line, pos);
            continue;
       }
       printf("%s(%d): Line%d: param=%s\n",__func__,__LINE__,line,pos);
       if(!os_strncmp(pos,"ssid",pos2 - pos))
       {
            pos2++;
            if (*pos2 == '"')
            {
        		const char *pos3;
        		char *str;
        		pos2++;
        		pos3 = os_strrchr(pos2, '"');
        		if (pos3 == NULL || pos3[1] != '\0')
        			break;
        		sval_len = pos3 - pos2;
        		str = dup_binstr(pos2, sval_len);
        		if (str == NULL)
        			break;
                
            	if(sval_len > SSID_MAX_LEN || sval_len <= 0)
                {
                    wpa_printf(MSG_ERROR,"Line %d: Invalid SSID '%s'.",line,pos2);
                    break;
                }
                else
                {
                    apinfo->ssid = str;
                    continue;
                }

        	}
            else
            {
                    wpa_printf(MSG_ERROR, "Line %d: Invalid SSID '%s'.", line, pos);
                    break;
            }
       }
       else if(!os_strncmp(pos,"psk",pos2 - pos))
       {
            sval_len = os_strlen(pos) - (pos2-pos);
            if(wpa_config_parse_psk(apinfo,line,pos2+1) < 0)
                break;
            else
                continue;
       }
       else if(!os_strncmp(pos,"key_mgmt",pos2 - pos))
       {
            if(wpa_config_parse_key_mgmt(apinfo,line,pos2+1) < 0)
                break;
            else
                continue;
       }
       else if(!os_strncmp(pos,"proto",pos2 - pos))
       {
            if(wpa_config_parse_proto(apinfo,line,pos2+1) < 0)
                break;
            else
                continue;
       }
       else if(!os_strncmp(pos,"pairwise",pos2 - pos))
       {
            if(wpa_config_parse_pairwise(apinfo,line,pos2+1) < 0)
                break;
            else
                continue;
       }
       else if(!os_strncmp(pos,"group",pos2 - pos))
       {
            if(wpa_config_parse_group(apinfo,line,pos2+1) < 0)
                break;
            else
                continue;
       }
       else
       {
            wpa_printf(MSG_ERROR,"Unknow param %s!\n",pos);
       }
    }


    fclose(f);
    return apinfo;

}

/**STA 的基本配置信息，后面可以从flash中读取**/
struct wpa_ssid * ssid_init(void)
{
    struct wpa_ssid *apinfo;

    apinfo = wpa_config_read("/var/test.conf");
    printf("ssid=%s,psk=%s,key_mgmt=0x%x,proto=0x%x,pairwise_cipher=0x%x,group_cipher=0x%x\n",
                apinfo->ssid,apinfo->passphrase,apinfo->key_mgmt,apinfo->proto,
                apinfo->pairwise_cipher,apinfo->group_cipher);

/***************************************************************
    
//    apinfo->ssid = "CMCC-abc888_wpa";
    os_strlcpy(apinfo->ssid,"CMCC-abc888_wpa",15);
    apinfo->ssid[15]='\0';
    apinfo->ssid_len = strlen(apinfo->ssid);
//    apinfo->passphrase = "87654321";
    os_strlcpy(apinfo->passphrase,"87654321",8);
    apinfo->passphrase[8]='\0';
    
    apinfo->key_mgmt = WPA_KEY_MGMT_PSK;
    apinfo->pairwise_cipher = WPA_CIPHER_CCMP;
    apinfo->group_cipher = WPA_CIPHER_TKIP;
    apinfo->proto = WPA_PROTO_RSN;
****************************************************************/
    apinfo->id = 0;
    apinfo->ssid_len = strlen(apinfo->ssid);
    memset(apinfo->psk,0,PMK_LEN);
    apinfo->psk_set = 0;

    return apinfo;

}

static u8 * wpa_alloc_eapol(void *ctx, u8 type,
                const void *data, u16 data_len,
                size_t *msg_len, void **data_pos)
{
    struct wpa_supplicant *wpa_s = ctx;
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
static int wpa_ether_send(void *ctx, const u8 *dest,
              u16 proto, const u8 *buf, size_t len)
{
    struct wpa_supplicant *wpa_s = ctx;
    if (wpa_s->l2)
    {
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
    ASSERT(ctx != NULL);
    
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
    memset(sm->rx_replay_counter,0,WPA_REPLAY_COUNTER_LEN);
    sm->rx_replay_counter_set = 0;
    /***********************************************/
    
    sm->dot11RSNAConfigPMKLifetime = 43200;
    sm->dot11RSNAConfigPMKReauthThreshold = 70;
    sm->dot11RSNAConfigSATimeout = 60;

    sm->pmksa = (void *) -1;//pmksa_cache_init(wpa_sm_pmksa_free_cb, sm, sm);
    if (sm->pmksa == NULL)
    {
        wpa_msg(sm->ctx->msg_ctx, MSG_ERROR,"RSN: PMKSA cache initialization failed");
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
    ctx->deauthenticate = wpa_supplicant_deauthenticate;
    ctx->set_state = wpa_supplicant_set_state;
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
    
    /*根据密码、ssid、ssid length，生成PMK*/
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
