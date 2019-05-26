#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/time.h>
#include <sys/select.h>
#include <sys/socket.h>       // needed for socket(
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/wireless.h>
#include <net/if_arp.h>
#include <errno.h>
#include "define.h"


#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif


struct driver_atheros_data 
{
	void *ctx;
//	struct netlink_data *netlink;
	int ioctl_sock;
	char ifname[IFNAMSIZ + 1];
};


#ifndef __packed
#define __packed    __attribute__((__packed__))
#endif
struct ieee80211req_key {
	u_int8_t	ik_type;	/* key/cipher type */
	u_int8_t	ik_pad;
	u_int16_t	ik_keyix;	/* key index */
	u_int8_t	ik_keylen;	/* key length in bytes */
	u_int8_t	ik_flags;
/* NB: IEEE80211_KEY_XMIT and IEEE80211_KEY_RECV defined elsewhere */
#define	IEEE80211_KEY_DEFAULT	0x80	/* default xmit key */
	u_int8_t	ik_macaddr[IEEE80211_ADDR_LEN];
	u_int64_t	ik_keyrsc;	/* key receive sequence counter */
	u_int64_t	ik_keytsc;	/* key transmit sequence counter */
	u_int8_t	ik_keydata[IEEE80211_KEYBUF_SIZE+IEEE80211_MICBUF_SIZE];
} __packed;

#define IEEE80211_MAX_WPA_KEK_LEN 64
#define IEEE80211_FILS_NONCE_LEN  16
struct ieee80211req_fils_aad {
    u_int8_t    ANonce[IEEE80211_FILS_NONCE_LEN];
    u_int8_t    SNonce[IEEE80211_FILS_NONCE_LEN];
    u_int8_t    kek[IEEE80211_MAX_WPA_KEK_LEN];
    u_int32_t   kek_len;
} __packed;

/*
 * MLME state manipulation request.  IEEE80211_MLME_ASSOC
 * only makes sense when operating as a station.  The other
 * requests can be used when operating as a station or an
 * ap (to effect a station).
 */
struct ieee80211req_mlme {
	u_int8_t	im_op;		/* operation to perform */
#define	IEEE80211_MLME_ASSOC		1	/* associate station */
#define	IEEE80211_MLME_DISASSOC		2	/* disassociate station */
#define	IEEE80211_MLME_DEAUTH		3	/* deauthenticate station */
#define	IEEE80211_MLME_AUTHORIZE	4	/* authorize station */
#define	IEEE80211_MLME_UNAUTHORIZE	5	/* unauthorize station */
#define	IEEE80211_MLME_STOP_BSS		6	/* stop bss */
#define	IEEE80211_MLME_CLEAR_STATS	7	/* clear station statistic */
#define	IEEE80211_MLME_AUTH	        8	/* auth resp to station */
#define	IEEE80211_MLME_REASSOC	    9	/* reassoc to station */
#define	IEEE80211_MLME_AUTH_FILS    10	/* AUTH - when FILS enabled */
	u_int8_t	im_ssid_len;	/* length of optional ssid */
	u_int16_t	im_reason;	/* 802.11 reason code */
	u_int16_t	im_seq;	        /* seq for auth */
	u_int8_t	im_macaddr[IEEE80211_ADDR_LEN];
	u_int8_t	im_ssid[32];
	u_int8_t        im_optie[IEEE80211_MAX_OPT_IE];
	u_int16_t       im_optie_len;
	struct      ieee80211req_fils_aad  fils_aad;
} __packed;

/**
 * struct wpa_driver_associate_params - Association parameters
 * Data for struct wpa_driver_ops::associate().
 */
struct wpa_driver_associate_params
{
    int auth_alg;
    u8 *bssid;
    int drop_unencrypted;
    unsigned int group_suite;
    unsigned int key_mgmt_suite;
    unsigned int pairwise_suite;
    u8 *ssid;
    size_t ssid_len;
    u8 *wpa_ie;
    size_t wpa_ie_len;
};

u8 default_wpa_ie[200]={0x30,0x14,0x01,0x00,0x00,0x0f,0xac,0x02,0x01,0x00,0x00,0x0f,0xac,
                          0x04,0x01,0x00,0x00,0x0f,0xac,0x02,0x00,0x00,0x3b,0x04,0x51,0x51,0x53,0x54};

u8 default_bssid[IEEE80211_ADDR_LEN]={0xc8,0x3a,0x35,0x1f,0x32,0x96};

static int set80211priv(struct driver_atheros_data *drv, int op, void *data, int len,int show_err)
{
	struct iwreq iwr;

printf("GJF: %s(%d): len=%d\n",__func__,__LINE__,len);
	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
printf("GJF: %s(%d): IFNAMSIZ=%d\n",__func__,__LINE__,IFNAMSIZ);

		/*
		 * Argument data too big for inline transfer; setup a
		 * parameter block instead; the kernel will transfer
		 * the data for the driver.
		 */
	iwr.u.data.pointer = data;
	iwr.u.data.length = len;
printf("GJF: %s(%d): ioctl\n",__func__,__LINE__);
//wpa_hexdump(MSG_DEBUG, "EAPOL: ioctl set key",iwr.u.data.pointer,iwr.u.data.length);

	if (ioctl(drv->ioctl_sock, op, &iwr) < 0) 
    {
printf("GJF: %s(%d): show_err=%d\n",__func__,__LINE__,show_err);
//		if (show_err) 
//        {
//			printf("%s: op=%x (%s) len=%d "
//				   "name=%s failed: %d (%s)",
//				   __func__, op,
//				   athr_get_ioctl_name(op),
//				   iwr.u.data.length, iwr.u.name,
//				   errno, strerror(errno));
//		}
		return -1;
	}
printf("GJF: %s(%d):\n",__func__,__LINE__);

	return 0;
}


void * driver_atheros_init(const char *ifname)
{
	struct driver_atheros_data *drv;

	drv = (struct driver_atheros_data *)malloc(sizeof(*drv));
	if (drv == NULL)
		return NULL;

	strncpy(drv->ifname, ifname, sizeof(drv->ifname));

	drv->ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (drv->ioctl_sock < 0) 
    {
		perror("socket(PF_INET,SOCK_DGRAM)");
		goto err1;
	}

//	if (linux_get_ifhwaddr(drv->ioctl_sock, drv->ifname, drv->own_addr) <0)
//		goto err1;

	return drv;

err1:
	free(drv);
	return NULL;
}

void set_key(struct driver_atheros_data *priv,char *ifname)
{

    struct ieee80211req_key k;
    struct driver_atheros_data *drv=priv;
    memset(&k,0,sizeof(k));
    k.ik_type = 0x3;
    k.ik_keyix = 0xffff;
    k.ik_keylen = 0x10;
    k.ik_flags = 0x3;

    memcpy(k.ik_macaddr,default_bssid,IEEE80211_ADDR_LEN);
    printf("size_k=%ld\n",sizeof(k));
    set80211priv(drv, IEEE80211_IOCTL_SETKEY, &k, sizeof(k), 1);

}

/*
 * Function to call a sub-ioctl for setparam.
 * data + 0 = mode = subioctl number
 * data +4 = int parameter.
 */
static int
set80211param_ifname(struct driver_atheros_data *drv, const char *ifname,
		     int op, int arg, int show_err)
{
	struct iwreq iwr;

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, ifname, IFNAMSIZ);
	iwr.u.mode = op;
	os_memcpy(iwr.u.name + sizeof(__u32), &arg, sizeof(arg));

//	printf("%s: ifname=%s subioctl=%d (%s) arg=%d",
//		   __func__, ifname, op, athr_get_param_name(op), arg);
	if (ioctl(drv->ioctl_sock, IEEE80211_IOCTL_SETPARAM, &iwr) < 0) {
		if (show_err)
			printf("athr: "
				   "ioctl[IEEE80211_IOCTL_SETPARAM] failed: "
				   "%s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static int set80211param(struct driver_atheros_data *drv, int op, int arg, int show_err)
{
	return set80211param_ifname(drv, drv->ifname, op, arg, show_err);
}


/**
 * driver_atheros_set_ssid - Set SSID, SIOCSIWESSID
 * @priv: Pointer to private wext data from driver_atheros_init()
 * @ssid: SSID
 * @ssid_len: Length of SSID (0..32)
 * Returns: 0 on success, -1 on failure
 */
int driver_atheros_set_ssid(void *priv, const u8 *ssid, size_t ssid_len)
{
	struct driver_atheros_data *drv = priv;
	struct iwreq iwr;
	int ret = 0;
	char buf[33];

	if (ssid_len > 32)
		return -1;

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
	/* flags: 1 = ESSID is active, 0 = not (promiscuous) */
	iwr.u.essid.flags = (ssid_len != 0);
	os_memset(buf, 0, sizeof(buf));
	os_memcpy(buf, ssid, ssid_len);
	iwr.u.essid.pointer = (caddr_t) buf;

	iwr.u.essid.length = ssid_len;

	if (ioctl(drv->ioctl_sock, SIOCSIWESSID, &iwr) < 0) {
		perror("ioctl[SIOCSIWESSID]");
		ret = -1;
	}

	return ret;
}
static int driver_atheros_set_auth_alg(struct driver_atheros_data *drv,
				       unsigned int key_mgmt_suite,
				       int auth_alg)
{
	int authmode;
	if (key_mgmt_suite == WPA_KEY_MGMT_IEEE8021X)
		authmode = IEEE80211_AUTH_8021X;
	else if (key_mgmt_suite == WPA_KEY_MGMT_PSK)
		authmode = IEEE80211_AUTH_WPA;
	else if ((auth_alg & WPA_AUTH_ALG_OPEN) &&
		 (auth_alg & WPA_AUTH_ALG_SHARED))
		authmode = IEEE80211_AUTH_AUTO;
	else if (auth_alg & WPA_AUTH_ALG_SHARED)
		authmode = IEEE80211_AUTH_SHARED;
	else
		authmode = IEEE80211_AUTH_OPEN;

	return set80211param(drv, IEEE80211_PARAM_AUTHMODE, authmode, 1);
}

static int driver_atheros_set_cipher(struct driver_atheros_data *drv, int type,
				     unsigned int suite)
{
	int cipher;

	printf("athr: Set cipher type=%d suite=%d\n",
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

	printf("athr: cipher=%d\n", cipher);

	return set80211param(drv, type, cipher, 1);
}

static int
driver_atheros_set_wpa_ie(struct driver_atheros_data *drv,
			  const u8 *wpa_ie, size_t wpa_ie_len)
{
	struct iwreq iwr;

	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
	/* NB: SETOPTIE is not fixed-size so must not be inlined */
	iwr.u.data.pointer = (void *) wpa_ie;
	iwr.u.data.length = wpa_ie_len;
	printf("WPA IE: ifname:%s len=%d\n",
		   drv->ifname, (int)wpa_ie_len);

	if (ioctl(drv->ioctl_sock, IEEE80211_IOCTL_SETOPTIE, &iwr) < 0) {
		printf("athr: ioctl[IEEE80211_IOCTL_SETOPTIE] "
			   "failed: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}


static int
driver_atheros_set_mlme(struct driver_atheros_data *drv, int op,
			const u8 *bssid, const u8 *ssid)
{
	struct ieee80211req_mlme mlme;
	int ret = 0;

	os_memset(&mlme, 0, sizeof(mlme));
	mlme.im_op = op;
	if (bssid) {
		os_memcpy(mlme.im_macaddr, bssid, IEEE80211_ADDR_LEN);
		printf("Associating.. AP BSSID=" MACSTR ", "
			   "ssid=%s, op=%d\n",
			   MAC2STR(bssid), ssid, op);
	}

	printf(" %s: OP mode = %d\n", __func__, op);

	if (set80211priv(drv, IEEE80211_IOCTL_SETMLME, &mlme,
			 sizeof(mlme), 1) < 0) {
		printf("%s: SETMLME[ASSOC] failed\n", __func__);
		ret = -1;
	}

	return ret;
}

static int driver_atheros_associate(void *priv,struct wpa_driver_associate_params *params)
{
	struct driver_atheros_data *drv = priv;
	int ret = 0, privacy = 1;
    int i;
//	wpa_printf(MSG_DEBUG, "athr: Associate: mode=%d p2p=%d freq=%d",
//		   params->mode, params->p2p, params->freq);

//	drv->last_assoc_mode = params->mode;
//	drv->assoc_event_sent = 0;


//	wpa_hexdump(MSG_DEBUG, "athr: Association IEs",
//		    params->wpa_ie, params->wpa_ie_len);

	if (driver_atheros_set_ssid(drv, params->ssid, params->ssid_len) < 0)
		ret = -1;

	if (params->pairwise_suite == WPA_CIPHER_NONE &&
	    params->group_suite == WPA_CIPHER_NONE &&
	    params->key_mgmt_suite == WPA_KEY_MGMT_NONE)
		privacy = 0;


	set80211param(drv, IEEE80211_PARAM_DROPUNENCRYPTED,params->drop_unencrypted, 1);
    
	if (privacy) {
		if (params->key_mgmt_suite == WPA_KEY_MGMT_IEEE8021X ||
		    params->key_mgmt_suite == WPA_KEY_MGMT_PSK) {
			printf(" *** KEY MGMT is 2\n");
		    if (params->wpa_ie_len &&
		        set80211param(drv, IEEE80211_PARAM_WPA,
		                      params->wpa_ie[0] == WLAN_EID_RSN ?
				      2 : 1, 1) < 0)
				ret = -1;
		} else if (set80211param(drv, IEEE80211_PARAM_WPA, 0, 1) < 0) {
			printf(" KEY MGMT is 0\n");
			ret = -1;
		}
	}

	if (driver_atheros_set_auth_alg(drv, params->key_mgmt_suite,
					params->auth_alg) < 0) 
	{
		printf("set_auth_alg failed suite=%d, alg=%d\n",
			   params->key_mgmt_suite, params->auth_alg);
		ret = -1;
	}

	if (params->wpa_ie_len) {
		if (params->key_mgmt_suite != WPA_KEY_MGMT_NONE &&
		    driver_atheros_set_cipher(drv, IEEE80211_IOC_UCASTCIPHER,
					      params->pairwise_suite) < 0)
			ret = -1;
		if (params->key_mgmt_suite != WPA_KEY_MGMT_NONE &&
		    driver_atheros_set_cipher(drv, IEEE80211_IOC_MCASTCIPHER,
					      params->group_suite) < 0)
			ret = -1;

		if (driver_atheros_set_wpa_ie(drv, params->wpa_ie,
					      params->wpa_ie_len) < 0)
			ret = -1;
	} else {
		set80211param(drv, IEEE80211_PARAM_CLR_APPOPT_IE, 1, 1);
	}

	/*
	 * Privacy flag seem to be set at all times for station. Otherwise
	 * it does not connect to GO which always has privacy flag set.
	 */
	if (set80211param(drv, IEEE80211_PARAM_PRIVACY, privacy, 1) < 0)
		ret = -1;

	if (set80211param(drv, IEEE80211_PARAM_ROAMING, 2, 1) < 0)
			ret = -1;
    
    for(i=0;i<40;i++)
    {
        printf("#");
        sleep(1);
    }
    printf("\n");
    
	if (driver_atheros_set_mlme(drv, IEEE80211_MLME_ASSOC, params->bssid,
				    params->ssid) < 0)
		ret = -1;

	return ret;
}
int set_associate(struct driver_atheros_data *priv,char *ifname)
{

    struct wpa_driver_associate_params params;

    params.auth_alg = WPA_AUTH_ALG_OPEN;
    params.bssid = default_bssid;
    params.drop_unencrypted = 1;
    params.group_suite = 8;
    params.key_mgmt_suite = 2;
    params.pairwise_suite = 16;
    params.ssid = "CMCC-abc888_wpa";
    params.ssid_len = 15;
    params.wpa_ie = default_wpa_ie;
    params.wpa_ie_len = 28;

    return driver_atheros_associate(priv,&params);
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
			printf("athr: Failed to clear BSSID");
	}
}

int main(int argc,char** argv)
{
    char ifname[IFNAMSIZ]="ath8";
    char op[10]="auth";
    struct driver_atheros_data *drv=NULL;
    int ret=-1;
    
    argv++;
    while (*argv != NULL)
    {
        if(!strcmp(*argv,"-i"))
        {
            argv++;
            if(*argv != NULL)
            {
                memset(ifname,0,IFNAMSIZ);
                strncpy(ifname,*argv,strlen(*argv));
                ifname[IFNAMSIZ-1] = '\0';
            }
            else
                printf("ifname is NULL!\n");
        }
        else if(!strcmp(*argv,"-o"))
        {
            argv++;
            if(*argv != NULL)
            {
                memset(op,0,10);
                strncpy(op,*argv,strlen(*argv));
                printf("size_op=%d,op=%s\n",strlen(*argv),op);
                op[9] = '\0';
            }
            else
                printf("op is NULL!\n");
        }

        argv++;
    }
    
    printf("ifname=%s,op=%s\n",ifname,op);
    drv = driver_atheros_init(ifname);
    assert(drv != NULL);

    if(!strncmp(op,"auth",4))
    {
        while(set_associate(drv,ifname) < 0)
        {
             printf("######## set_associate is failure! ######\n");
            sleep(5);
        }
        printf("######## associate Successful! ######\n");
    }
    else if(!strncmp(op,"deauth",6))
    {
        
        driver_atheros_set_mlme(drv,IEEE80211_MLME_DEAUTH,NULL,NULL);
        athr_clear_bssid(drv);
        printf("######## Deauth Successful! ######\n");

    }
    else
    {
        printf("Unknow commde!\n");
    }
    return 0;
}
