#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()
#include <netdb.h>            // struct addrinfo
#include "main.h"
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/time.h>
#include <sys/select.h>
#include <sys/socket.h>       // needed for socket(
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netpacket/packet.h>
#include <net/if.h>
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
//#include "list.h"

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
};

#if 0

/*
 * Table of network configuration variables. This table is used to parse each
 * network configuration variable, e.g., each line in wpa_supplicant.conf file
 * that is inside a network block.
 *
 * This table is generated using the helper macros defined above and with
 * generous help from the C pre-processor. The field name is stored as a string
 * into .name and for STR and INT types, the offset of the target buffer within
 * struct wpa_ssid is stored in .param1. .param2 (if not NULL) is similar
 * offset to the field containing the length of the configuration variable.
 * .param3 and .param4 can be used to mark the allowed range (length for STR
 * and value for INT).
 *
 * For each configuration line in wpa_supplicant.conf, the parser goes through
 * this table and select the entry that matches with the field name. The parser
 * function (.parser) is then called to parse the actual value of the field.
 *
 * This kind of mechanism makes it easy to add new configuration parameters,
 * since only one line needs to be added into this table and into the
 * struct wpa_ssid definition if the new variable is either a string or
 * integer. More complex types will need to use their own parser and writer
 * functions.
 */
static const struct parse_data ssid_fields[] = {
	{ STR_RANGE(ssid, 0, SSID_MAX_LEN) },
	{ FUNC(bssid) },
//	{ FUNC(bssid_blacklist) },
//	{ FUNC(bssid_whitelist) },
	{ FUNC_KEY(psk) },
//	{ INT(mem_only_psk) },
	{ FUNC(proto) },
	{ FUNC(key_mgmt) },
	{ FUNC(pairwise) },
	{ FUNC(group) },
	{ FUNC(auth_alg) },
//	{ FUNC_KEY(wep_key0) },
//	{ FUNC_KEY(wep_key1) },
//	{ FUNC_KEY(wep_key2) },
//	{ FUNC_KEY(wep_key3) },
//	{ INT(wep_tx_keyidx) },
	{ INT(priority) },
//	{ INT_RANGE(proactive_key_caching, 0, 1) },
//	{ INT_RANGE(mixed_cell, 0, 1) },
//	{ INT_RANGE(frequency, 0, 65000) },
//	{ INT_RANGE(fixed_freq, 0, 1) },
	{ INT(wpa_ptk_rekey) },
	{ INT(group_rekey) },
//	{ STR(bgscan) },
//	{ INT_RANGE(ignore_broadcast_ssid, 0, 2) },
//	{ INT(ap_max_inactivity) },
//	{ INT(dtim_period) },
//	{ INT(beacon_int) },
	{ INT_RANGE(mac_addr, 0, 2) },
//	{ INT_RANGE(pbss, 0, 2) },
//	{ INT_RANGE(wps_disabled, 0, 1) },
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
    printf("%s(%d): bssid="MACSTR"\n",__func__,__LINE__,MAC2STR(ifr.ifr_hwaddr.sa_data));

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
	if (drv == NULL)
		return NULL;

	os_strlcpy(drv->ifname, ifname, sizeof(drv->ifname));

	drv->ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (drv->ioctl_sock < 0) 
    {
		perror("socket(PF_INET,SOCK_DGRAM)");
		goto err1;
	}

	if (linux_get_ifhwaddr(drv->ioctl_sock, drv->ifname, drv->own_addr) <0)
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
    printf("%s(%d): own_addr="MACSTR"\n",__func__,__LINE__,MAC2STR(l2->own_addr));
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
struct wpa_ssid * ssid_init(void)
{
	struct wpa_ssid *apinfo;

	apinfo = os_zalloc(sizeof(*apinfo));
	if (apinfo == NULL)
		return NULL;

    apinfo->id = 0;
    apinfo->ssid = "CMCC-abc888_wpa";
    apinfo->ssid_len = strlen(apinfo->ssid);
    apinfo->passphrase = "87654321";
    apinfo->key_mgmt = WPA_KEY_MGMT_PSK;
    apinfo->pairwise_cipher = WPA_CIPHER_CCMP | WPA_CIPHER_TKIP;
    apinfo->group_cipher = WPA_CIPHER_CCMP | WPA_CIPHER_TKIP;
    apinfo->proto = WPA_PROTO_RSN | WPA_PROTO_WPA;
    memset(apinfo->psk,0,PMK_LEN);
    apinfo->psk_set = 0;

    return apinfo;

}

/**
 * wpa_sm_init - Initialize WPA state machine
 * @ctx: Context pointer for callbacks; this needs to be an allocated buffer
 * Returns: Pointer to the allocated WPA state machine data
 *
 * This function is used to allocate a new WPA state machine and the returned
 * value is passed to all WPA state machine calls.
 */
struct wpa_sm * sm_init(struct driver_atheros_data *drv_ather,struct wpa_ssid *apinfo)
{
    ASSERT(drv_ather);
    
	struct wpa_sm *sm;

	sm = os_zalloc(sizeof(*sm));
	if (sm == NULL)
		return NULL;
	dl_list_init(&sm->pmksa_candidates);
	sm->renew_snonce = 1;
	sm->ctx = NULL;
    
    /***************** add by gjf *******************/
    if(apinfo == NULL)
    {
        sm->proto = WPA_PROTO_RSN; 
        sm->key_mgmt = WPA_KEY_MGMT_PSK;
        sm->pairwise_cipher = WPA_CIPHER_CCMP;
        sm->group_cipher = WPA_CIPHER_CCMP;
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
    driver_atheros_get_bssid(drv_ather,sm->bssid);
    printf("%s(%d): Get BSSID="MACSTR"\n",__func__,__LINE__,MAC2STR(sm->bssid));
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

#if 0
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
    while (fgets(buf, sizeof(buf), stream)) {
        buf[sizeof(buf) - 1] = '\0';
        if (newline_terminated(buf, sizeof(buf)))
            return;
    }
}

#ifndef NO_CONFIG_WRITE
static char * wpa_config_write_int(const struct parse_data *data,
				   struct wpa_ssid *ssid)
{
	int *src, res;
	char *value;

	src = (int *) (((u8 *) ssid) + (long) data->param1);

	value = os_malloc(20);
	if (value == NULL)
		return NULL;
	res = os_snprintf(value, 20, "%d", *src);
	if (os_snprintf_error(20, res)) {
		os_free(value);
		return NULL;
	}
	value[20 - 1] = '\0';
	return value;
}

static int wpa_config_parse_int(const struct parse_data *data,
				struct wpa_ssid *ssid,int line, const char *value)
{
	int val, *dst;
	char *end;

	dst = (int *) (((u8 *) ssid) + (long) data->param1);
	val = strtol(value, &end, 0);
	if (*end) {
		wpa_printf(MSG_ERROR, "Line %d: invalid number \"%s\"",
			   line, value);
		return -1;
	}

	if (*dst == val)
		return 1;
	*dst = val;
	wpa_printf(MSG_MSGDUMP, "%s=%d (0x%x)", data->name, *dst, *dst);

	if (data->param3 && *dst < (long) data->param3) {
		wpa_printf(MSG_ERROR, "Line %d: too small %s (value=%d "
			   "min_value=%ld)", line, data->name, *dst,
			   (long) data->param3);
		*dst = (long) data->param3;
		return -1;
	}

	if (data->param4 && *dst > (long) data->param4) {
		wpa_printf(MSG_ERROR, "Line %d: too large %s (value=%d "
			   "max_value=%ld)", line, data->name, *dst,
			   (long) data->param4);
		*dst = (long) data->param4;
		return -1;
	}

	return 0;
}
static char * wpa_config_write_string_ascii(const u8 *value, size_t len)
{
	char *buf;

	buf = os_malloc(len + 3);
	if (buf == NULL)
		return NULL;
	buf[0] = '"';
	os_memcpy(buf + 1, value, len);
	buf[len + 1] = '"';
	buf[len + 2] = '\0';

	return buf;
}


static char * wpa_config_write_string_hex(const u8 *value, size_t len)
{
	char *buf;

	buf = os_zalloc(2 * len + 1);
	if (buf == NULL)
		return NULL;
	wpa_snprintf_hex(buf, 2 * len + 1, value, len);

	return buf;
}


static char * wpa_config_write_string(const u8 *value, size_t len)
{
	if (value == NULL)
		return NULL;

	if (is_hex(value, len))
		return wpa_config_write_string_hex(value, len);
	else
		return wpa_config_write_string_ascii(value, len);
}


static char * wpa_config_write_str(const struct parse_data *data,
				   struct wpa_ssid *ssid)
{
	size_t len;
	char **src;

	src = (char **) (((u8 *) ssid) + (long) data->param1);
	if (*src == NULL)
		return NULL;

	if (data->param2)
		len = *((size_t *) (((u8 *) ssid) + (long) data->param2));
	else
		len = os_strlen(*src);

	return wpa_config_write_string((const u8 *) *src, len);
}

#endif /* NO_CONFIG_WRITE */


static int wpa_config_parse_bssid(const struct parse_data *data,
				  struct wpa_ssid *ssid, int line,
				  const char *value)
{
	if (value[0] == '\0' || os_strcmp(value, "\"\"") == 0 ||
	    os_strcmp(value, "any") == 0) {
		ssid->bssid_set = 0;
		wpa_printf(MSG_MSGDUMP, "BSSID any");
		return 0;
	}
	if (hwaddr_aton(value, ssid->bssid)) {
		wpa_printf(MSG_ERROR, "Line %d: Invalid BSSID '%s'.",
			   line, value);
		return -1;
	}
	ssid->bssid_set = 1;
	wpa_hexdump(MSG_MSGDUMP, "BSSID", ssid->bssid, ETH_ALEN);
	return 0;
}




static int wpa_config_parse_group(const struct parse_data *data,
				  struct wpa_ssid *ssid, int line,
				  const char *value)
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

static int wpa_config_parse_pairwise(const struct parse_data *data,
				     struct wpa_ssid *ssid, int line,
				     const char *value)
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

static int wpa_config_parse_key_mgmt(const struct parse_data *data,
				     struct wpa_ssid *ssid, int line,
				     const char *value)
{
	int val = 0, last, errors = 0;
	char *start, *end, *buf;

	buf = os_strdup(value);
	if (buf == NULL)
		return -1;
	start = buf;

	while (*start != '\0') {
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
#ifdef CONFIG_IEEE80211R
		else if (os_strcmp(start, "FT-PSK") == 0)
			val |= WPA_KEY_MGMT_FT_PSK;
		else if (os_strcmp(start, "FT-EAP") == 0)
			val |= WPA_KEY_MGMT_FT_IEEE8021X;
#endif /* CONFIG_IEEE80211R */
#ifdef CONFIG_IEEE80211W
		else if (os_strcmp(start, "WPA-PSK-SHA256") == 0)
			val |= WPA_KEY_MGMT_PSK_SHA256;
		else if (os_strcmp(start, "WPA-EAP-SHA256") == 0)
			val |= WPA_KEY_MGMT_IEEE8021X_SHA256;
#endif /* CONFIG_IEEE80211W */
#ifdef CONFIG_WPS
		else if (os_strcmp(start, "WPS") == 0)
			val |= WPA_KEY_MGMT_WPS;
#endif /* CONFIG_WPS */
#ifdef CONFIG_SAE
		else if (os_strcmp(start, "SAE") == 0)
			val |= WPA_KEY_MGMT_SAE;
		else if (os_strcmp(start, "FT-SAE") == 0)
			val |= WPA_KEY_MGMT_FT_SAE;
#endif /* CONFIG_SAE */
#ifdef CONFIG_HS20
		else if (os_strcmp(start, "OSEN") == 0)
			val |= WPA_KEY_MGMT_OSEN;
#endif /* CONFIG_HS20 */
#ifdef CONFIG_SUITEB
		else if (os_strcmp(start, "WPA-EAP-SUITE-B") == 0)
			val |= WPA_KEY_MGMT_IEEE8021X_SUITE_B;
#endif /* CONFIG_SUITEB */
#ifdef CONFIG_SUITEB192
		else if (os_strcmp(start, "WPA-EAP-SUITE-B-192") == 0)
			val |= WPA_KEY_MGMT_IEEE8021X_SUITE_B_192;
#endif /* CONFIG_SUITEB192 */
#ifdef CONFIG_FILS
		else if (os_strcmp(start, "FILS-SHA256") == 0)
			val |= WPA_KEY_MGMT_FILS_SHA256;
		else if (os_strcmp(start, "FILS-SHA384") == 0)
			val |= WPA_KEY_MGMT_FILS_SHA384;
#ifdef CONFIG_IEEE80211R
		else if (os_strcmp(start, "FT-FILS-SHA256") == 0)
			val |= WPA_KEY_MGMT_FT_FILS_SHA256;
		else if (os_strcmp(start, "FT-FILS-SHA384") == 0)
			val |= WPA_KEY_MGMT_FT_FILS_SHA384;
#endif /* CONFIG_IEEE80211R */
#endif /* CONFIG_FILS */
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

	if (val == 0) {
		wpa_printf(MSG_ERROR,
			   "Line %d: no key_mgmt values configured.", line);
		errors++;
	}

	if (!errors && ssid->key_mgmt == val)
		return 1;
	wpa_printf(MSG_MSGDUMP, "key_mgmt: 0x%x", val);
	ssid->key_mgmt = val;
	return errors ? -1 : 0;
}

static int wpa_config_parse_proto(const struct parse_data *data,
				  struct wpa_ssid *ssid, int line,
				  const char *value)
{
	int val = 0, last, errors = 0;
	char *start, *end, *buf;

	buf = os_strdup(value);
	if (buf == NULL)
		return -1;
	start = buf;

	while (*start != '\0') {
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

	if (val == 0) {
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

static int wpa_config_parse_psk(const struct parse_data *data,
				struct wpa_ssid *ssid, int line,
				const char *value)
{
#ifdef CONFIG_EXT_PASSWORD
	if (os_strncmp(value, "ext:", 4) == 0) {
		str_clear_free(ssid->passphrase);
		ssid->passphrase = NULL;
		ssid->psk_set = 0;
		os_free(ssid->ext_psk);
		ssid->ext_psk = os_strdup(value + 4);
		if (ssid->ext_psk == NULL)
			return -1;
		wpa_printf(MSG_DEBUG, "PSK: External password '%s'",
			   ssid->ext_psk);
		return 0;
	}
#endif /* CONFIG_EXT_PASSWORD */

	if (*value == '"') {
#ifndef CONFIG_NO_PBKDF2
		const char *pos;
		size_t len;

		value++;
		pos = os_strrchr(value, '"');
		if (pos)
			len = pos - value;
		else
			len = os_strlen(value);
		if (len < 8 || len > 63) {
			wpa_printf(MSG_ERROR, "Line %d: Invalid passphrase "
				   "length %lu (expected: 8..63) '%s'.",
				   line, (unsigned long) len, value);
			return -1;
		}
		wpa_hexdump_ascii_key(MSG_MSGDUMP, "PSK (ASCII passphrase)",
				      (u8 *) value, len);
		if (has_ctrl_char((u8 *) value, len)) {
			wpa_printf(MSG_ERROR,
				   "Line %d: Invalid passphrase character",
				   line);
			return -1;
		}
		if (ssid->passphrase && os_strlen(ssid->passphrase) == len &&
		    os_memcmp(ssid->passphrase, value, len) == 0) {
			/* No change to the previously configured value */
			return 1;
		}
		ssid->psk_set = 0;
		str_clear_free(ssid->passphrase);
		ssid->passphrase = dup_binstr(value, len);
		if (ssid->passphrase == NULL)
			return -1;
		return 0;
#else /* CONFIG_NO_PBKDF2 */
		wpa_printf(MSG_ERROR, "Line %d: ASCII passphrase not "
			   "supported.", line);
		return -1;
#endif /* CONFIG_NO_PBKDF2 */
	}

	if (hexstr2bin(value, ssid->psk, PMK_LEN) ||
	    value[PMK_LEN * 2] != '\0') {
		wpa_printf(MSG_ERROR, "Line %d: Invalid PSK '%s'.",
			   line, value);
		return -1;
	}

	str_clear_free(ssid->passphrase);
	ssid->passphrase = NULL;

	ssid->psk_set = 1;
	wpa_hexdump_key(MSG_MSGDUMP, "PSK", ssid->psk, PMK_LEN);
	return 0;
}

 int wpa_config_parse_str(const struct parse_data *data,
				struct wpa_ssid *ssid,
				int line, const char *value)
{
	size_t res_len, *dst_len, prev_len;
	char **dst, *tmp;

	if (os_strcmp(value, "NULL") == 0) {
		wpa_printf(MSG_DEBUG, "Unset configuration string '%s'",
			   data->name);
		tmp = NULL;
		res_len = 0;
		goto set;
	}

	tmp = wpa_config_parse_string(value, &res_len);
	if (tmp == NULL) {
		wpa_printf(MSG_ERROR, "Line %d: failed to parse %s '%s'.",
			   line, data->name,
			   data->key_data ? "[KEY DATA REMOVED]" : value);
		return -1;
	}

	if (data->key_data) {
		wpa_hexdump_ascii_key(MSG_MSGDUMP, data->name,
				      (u8 *) tmp, res_len);
	} else {
		wpa_hexdump_ascii(MSG_MSGDUMP, data->name,
				  (u8 *) tmp, res_len);
	}

	if (data->param3 && res_len < (size_t) data->param3) {
		wpa_printf(MSG_ERROR, "Line %d: too short %s (len=%lu "
			   "min_len=%ld)", line, data->name,
			   (unsigned long) res_len, (long) data->param3);
		os_free(tmp);
		return -1;
	}

	if (data->param4 && res_len > (size_t) data->param4) {
		wpa_printf(MSG_ERROR, "Line %d: too long %s (len=%lu "
			   "max_len=%ld)", line, data->name,
			   (unsigned long) res_len, (long) data->param4);
		os_free(tmp);
		return -1;
	}

set:
	dst = (char **) (((u8 *) ssid) + (long) data->param1);
	dst_len = (size_t *) (((u8 *) ssid) + (long) data->param2);

	if (data->param2)
		prev_len = *dst_len;
	else if (*dst)
		prev_len = os_strlen(*dst);
	else
		prev_len = 0;
	if ((*dst == NULL && tmp == NULL) ||
	    (*dst && tmp && prev_len == res_len &&
	     os_memcmp(*dst, tmp, res_len) == 0)) {
		/* No change to the previously configured value */
		os_free(tmp);
		return 1;
	}

	os_free(*dst);
	*dst = tmp;
	if (data->param2)
		*dst_len = res_len;

	return 0;
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

/**
 * wpa_config_set_network_defaults - Set network default values
 * @ssid: Pointer to network configuration data
 */
void wpa_config_set_network_defaults(struct wpa_ssid *ssid)
{
	ssid->proto = DEFAULT_PROTO;
	ssid->pairwise_cipher = DEFAULT_PAIRWISE;
	ssid->group_cipher = DEFAULT_GROUP;
	ssid->key_mgmt = DEFAULT_KEY_MGMT;
	ssid->proactive_key_caching = -1;
	ssid->mac_addr = -1;
}

/**
 * wpa_config_set - Set a variable in network configuration
 * @ssid: Pointer to network configuration data
 * @var: Variable name, e.g., "ssid"
 * @value: Variable value
 * @line: Line number in configuration file or 0 if not used
 * Returns: 0 on success with possible change in the value, 1 on success with
 * no change to previously configured value, or -1 on failure
 *
 * This function can be used to set network configuration variables based on
 * both the configuration file and management interface input. The value
 * parameter must be in the same format as the text-based configuration file is
 * using. For example, strings are using double quotation marks.
 */
int wpa_config_set(struct wpa_ssid *ssid, const char *var, const char *value,
		   int line)
{
	size_t i;
	int ret = 0;

	if (ssid == NULL || var == NULL || value == NULL)
		return -1;

	for (i = 0; i < NUM_SSID_FIELDS; i++) {
		const struct parse_data *field = &ssid_fields[i];
		if (os_strcmp(var, field->name) != 0)
			continue;

		ret = field->parser(field, ssid, line, value);
		if (ret < 0) {
			if (line) {
				wpa_printf(MSG_ERROR, "Line %d: failed to "
					   "parse %s '%s'.", line, var, value);
			}
			ret = -1;
		}
		break;
	}
	if (i == NUM_SSID_FIELDS) {
		if (line) {
			wpa_printf(MSG_ERROR, "Line %d: unknown network field "
				   "'%s'.", line, var);
		}
		ret = -1;
	}

	return ret;
}

void wpa_config_update_psk(struct wpa_ssid *ssid)
{
    printf("gjf==> %s(%d):passphrase=%s,ssid=%s,ssid_len=%d\n",__func__,__LINE__,
            ssid->passphrase, ssid->ssid, ssid->ssid_len);
	pbkdf2_sha1(ssid->passphrase, ssid->ssid, ssid->ssid_len, 4096,ssid->psk, PMK_LEN);
	wpa_hexdump_key(MSG_MSGDUMP, "PSK (from passphrase)",ssid->psk, PMK_LEN);
	ssid->psk_set = 1;
}

static int wpa_config_validate_network(struct wpa_ssid *ssid, int line)
{
	int errors = 0;

	if (ssid->passphrase) {
		if (ssid->psk_set) {
			wpa_printf(MSG_ERROR, "Line %d: both PSK and "
				   "passphrase configured.", line);
			errors++;
		}
		wpa_config_update_psk(ssid);
	}



	if((ssid->group_cipher & (WPA_CIPHER_CCMP | WPA_CIPHER_GCMP |
                                  WPA_CIPHER_GCMP_256 |
				  WPA_CIPHER_CCMP_256)) &&
           (ssid->pairwise_cipher & (WPA_CIPHER_CCMP | WPA_CIPHER_GCMP |
                                     WPA_CIPHER_GCMP_256 |
				     WPA_CIPHER_CCMP_256)) &&
           !(ssid->pairwise_cipher & WPA_CIPHER_NONE)) {


                if ((ssid->group_cipher & WPA_CIPHER_CCMP_256) &&
                    !(ssid->pairwise_cipher & WPA_CIPHER_CCMP_256)){
                        /*
                         * Group cipher cannot be stronger `than the
                         * pairwise cipher.
                         */
                        wpa_printf(MSG_DEBUG, "Line %d: removed CCMP 256 from"
                                   " group cipher list since it was not"
                                   "allowed for pairwise cipher 0x%x",
                                   line,ssid->pairwise_cipher);
                        ssid->group_cipher &= ~WPA_CIPHER_CCMP_256;
                }

                if ((ssid->group_cipher & WPA_CIPHER_GCMP_256) &&
                    !(ssid->pairwise_cipher & (WPA_CIPHER_CCMP_256 |
                                               WPA_CIPHER_GCMP_256))){
                        /*
                         * Group cipher cannot be stronger `than the
                         * pairwise cipher.
                         */
                        wpa_printf(MSG_DEBUG, "Line %d: removed GCMP 256 from"
                                   " group cipher list since it was not"
                                   "allowed for pairwise cipher 0x%x",
                                   line,ssid->pairwise_cipher);
                        ssid->group_cipher &= ~WPA_CIPHER_GCMP_256;
                }

                if ((ssid->group_cipher & WPA_CIPHER_GCMP) &&
                    !(ssid->pairwise_cipher & (WPA_CIPHER_CCMP_256 |
                                               WPA_CIPHER_GCMP_256 |
                                               WPA_CIPHER_GCMP))){
                        /*
                         * Group cipher cannot be stronger `than the
                         * pairwise cipher.
                         */
                        wpa_printf(MSG_DEBUG, "Line %d: removed GCMP from"
                                   " group cipher list since it was not"
                                   "allowed for pairwise cipher 0x%x",
                                   line,ssid->pairwise_cipher);
                        ssid->group_cipher &= ~WPA_CIPHER_GCMP;
                }

	} else {
		ssid->group_cipher &= ~(WPA_CIPHER_CCMP | WPA_CIPHER_GCMP |
					WPA_CIPHER_GCMP_256 |
					WPA_CIPHER_CCMP_256);

	}

	return errors;
}

static struct wpa_ssid * wpa_config_read_network(FILE *f, int *line, int id)
{
    struct wpa_ssid *ssid;
    int errors = 0, end = 0;
    char buf[2000], *pos, *pos2;

    wpa_printf(MSG_MSGDUMP, "Line: %d - start of a new network block",
           *line);
    ssid = os_zalloc(sizeof(*ssid));
    memset(ssid,0,sizeof(*ssid));
    if (ssid == NULL)
        return NULL;
    dl_list_init(&ssid->psk_list);
    ssid->id = id;

    wpa_config_set_network_defaults(ssid);

    while (wpa_config_get_line(buf, sizeof(buf), f, line, &pos)) {
        if (os_strcmp(pos, "}") == 0) {
            end = 1;
            break;
        }

        pos2 = os_strchr(pos, '=');
        if (pos2 == NULL) {
            wpa_printf(MSG_ERROR, "Line %d: Invalid SSID line "
                   "'%s'.", *line, pos);
            errors++;
            continue;
        }

        *pos2++ = '\0';
        if (*pos2 == '"') {
            if (os_strchr(pos2 + 1, '"') == NULL) {
                wpa_printf(MSG_ERROR, "Line %d: invalid "
                       "quotation '%s'.", *line, pos2);
                errors++;
                continue;
            }
        }

        if (wpa_config_set(ssid, pos, pos2, *line) < 0)
            errors++;
    }

    if (!end) {
        wpa_printf(MSG_ERROR, "Line %d: network block was not "
               "terminated properly.", *line);
        errors++;
    }

    errors += wpa_config_validate_network(ssid, *line);


    return ssid;
}

struct wpa_ssid * wpa_config_read(const char *name, struct wpa_config *cfgp)
{
    FILE *f;
    char buf[512], *pos;
    int errors = 0, line = 0;
    struct wpa_ssid *ssid, *tail, *head;
    int id = 0;
    int cred_id = 0;
    
    if (name == NULL)
        return NULL;
    f = fopen(name, "r");
    
    if (f == NULL) 
    {
        wpa_printf(MSG_ERROR, "Failed to open config file '%s', "
               "error: %s", name, strerror(errno));
        return NULL;
    }

    while (wpa_config_get_line(buf, sizeof(buf), f, &line, &pos)) 
    {
        if (os_strcmp(pos, "network={") == 0)
        {
            ssid = wpa_config_read_network(f, &line, id++);
            if (ssid == NULL) 
            {
                wpa_printf(MSG_ERROR, "Line %d: failed to "
                       "parse network block.", line);
                errors++;
                continue;
            }
            
        }
    }
}
#endif
int main(int argc,char* argv[])
{

    struct wpa_sm *sm=NULL;
    struct wpa_ssid *ssid=NULL;
    struct driver_atheros_data *drv_ather = NULL;
    
    char ifname[30]="wlan0";
    if(argv[1] != NULL)
    {
        memset(ifname,0,30);
        strcpy(ifname,argv[1]);
    }

    printf("ifname = %s\n",ifname);

    drv_ather = driver_atheros_init(ifname);

    ssid = ssid_init();
    
    printf("gjf==> %s(%d):\n ssid=%s\n ssid_len=%ld\n passphrase=%s\n "
           "pairwise_cipher=%d\n group_cipher=%d\n key_mgmt=%d\n proto=%d\n",
        __func__,__LINE__,ssid->ssid,ssid->ssid_len,ssid->passphrase,
            ssid->pairwise_cipher,ssid->group_cipher,ssid->key_mgmt,ssid->proto);
    
    /*生成PMK*/
    pbkdf2_sha1(ssid->passphrase, ssid->ssid, ssid->ssid_len, 4096,ssid->psk, PMK_LEN);
    wpa_hexdump(MSG_ERROR, "WPA: Generate PMK",ssid->psk,PMK_LEN);

    sm = sm_init(drv_ather,ssid);

    l2_packet_init(ifname, NULL, ETH_P_PAE,driver_atheros_l2_read, sm, 0);
    return 0;
}
