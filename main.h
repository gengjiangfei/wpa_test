#ifndef MAIN_H
#define MAIN_H

#include "common.h"

#ifndef MACSTR
#define MACSTR      "%02x:%02x:%02x:%02x:%02x:%02x"
#endif

#ifndef MAC2STR
#define MAC2STR(a)  (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#endif

#define ASSERT(x)                                                               \
{                                                                               \
    if (!(x))                                                                   \
    {                                                                           \
        printf(__FILE__ ":%d assert " #x "failed\n", __LINE__);    \
    }                                                                           \
}

#define CONFIG_CRYPTO_INTERNAL
//enum {
//	MSG_EXCESSIVE, MSG_MSGDUMP, MSG_DEBUG, MSG_INFO, MSG_WARNING, MSG_ERROR
//};
#ifndef DL_LIST
#define DL_LIST
struct dl_list {
	struct dl_list *next;
	struct dl_list *prev;
};
#endif

#if 0
struct wpa_ssid {
    int id;
    u8 *ssid;//ssid - Service set identifier (network name)
    size_t ssid_len;//ssid_len - Length of the SSID
    char *passphrase;//psk - WPA pre-shared key (256 bits)

    u8 psk[32];//psk - WPA pre-shared key (256 bits)
    struct dl_list psk_list;//psk_list - Per-client PSKs (struct psk_list_entry)
    int psk_set;//Whether PSK field is configured
    
    int pairwise_cipher;//pairwise_cipher - Bitfield of allowed pairwise ciphers, WPA_CIPHER_*
    int group_cipher;//group_cipher - Bitfield of allowed group ciphers, WPA_CIPHER_*
    int key_mgmt;//key_mgmt - Bitfield of allowed key management protocols WPA_KEY_MGMT_*
    int proto;//proto - Bitfield of allowed protocols, WPA_PROTO_*
    /**
     * mac_addr - MAC address policy
     *
     * 0 = use permanent MAC address
     * 1 = use random MAC address for each ESS connection
     * 2 = like 1, but maintain OUI (with local admin bit set)
     *
     * Internally, special value -1 is used to indicate that the parameter
     * was not specified in the configuration (i.e., default behavior is
     * followed).
     */
    int mac_addr;
    
    /**
     * proactive_key_caching - Enable proactive key caching
     *
     * This field can be used to enable proactive key caching which is also
     * known as opportunistic PMKSA caching for WPA2. This is disabled (0)
     * by default unless default value is changed with the global okc=1
     * parameter. Enable by setting this to 1.
     *
     * Proactive key caching is used to make supplicant assume that the APs
     * are using the same PMK and generate PMKSA cache entries without
     * doing RSN pre-authentication. This requires support from the AP side
     * and is normally used with wireless switches that co-locate the
     * authenticator.
     *
     * Internally, special value -1 is used to indicate that the parameter
     * was not specified in the configuration (i.e., default behavior is
     * followed).
     */
    int proactive_key_caching;
};

/*
 * Structure for network configuration parsing. This data is used to implement
 * a generic parser for each network block variable. The table of configuration
 * variables is defined below in this file (ssid_fields[]).
 */
struct parse_data {
	/* Configuration variable name */
	char *name;

	/* Parser function for this variable. The parser functions return 0 or 1
	 * to indicate success. Value 0 indicates that the parameter value may
	 * have changed while value 1 means that the value did not change.
	 * Error cases (failure to parse the string) are indicated by returning
	 * -1. */
	int (*parser)(const struct parse_data *data, struct wpa_ssid *ssid,
		      int line, const char *value);

#ifndef NO_CONFIG_WRITE
	/* Writer function (i.e., to get the variable in text format from
	 * internal presentation). */
	char * (*writer)(const struct parse_data *data, struct wpa_ssid *ssid);
#endif /* NO_CONFIG_WRITE */

	/* Variable specific parameters for the parser. */
	void *param1, *param2, *param3, *param4;

	/* 0 = this variable can be included in debug output and ctrl_iface
	 * 1 = this variable contains key/private data and it must not be
	 *     included in debug output unless explicitly requested. In
	 *     addition, this variable will not be readable through the
	 *     ctrl_iface.
	 */
	int key_data;
};

int wpa_config_parse_str(const struct parse_data *data,struct wpa_ssid *ssid,int line, const char *value);
char * wpa_config_write_str(const struct parse_data *data,struct wpa_ssid *ssid);
int wpa_config_parse_bssid(const struct parse_data *data, struct wpa_ssid *ssid, int line,const char *value);
int wpa_config_parse_psk(const struct parse_data *data,struct wpa_ssid *ssid, int line,const char *value);
int wpa_config_parse_proto(const struct parse_data *data,struct wpa_ssid *ssid, int line,const char *value);
int wpa_config_parse_key_mgmt(const struct parse_data *data,struct wpa_ssid *ssid, int line,const char *value);
int wpa_config_parse_pairwise(const struct parse_data *data,struct wpa_ssid *ssid, int line,const char *value);
int wpa_config_parse_group(const struct parse_data *data,struct wpa_ssid *ssid, int line,const char *value);



#define OFFSET(v) ((void *) &((struct wpa_ssid *) 0)->v)

#ifdef NO_CONFIG_WRITE
#define _STR(f) #f, wpa_config_parse_str, OFFSET(f)
#define _STRe(f) #f, wpa_config_parse_str, OFFSET(eap.f)
#else /* NO_CONFIG_WRITE */
#define _STR(f) #f, wpa_config_parse_str, wpa_config_write_str, OFFSET(f)
#define _STRe(f) #f, wpa_config_parse_str, wpa_config_write_str, OFFSET(eap.f)
#endif /* NO_CONFIG_WRITE */

#define _STR_LEN(f) _STR(f), OFFSET(f ## _len)
#define _STR_RANGE(f, min, max) _STR_LEN(f), (void *) (min), (void *) (max)
#define STR_RANGE(f, min, max) _STR_RANGE(f, min, max), 0

#ifdef NO_CONFIG_WRITE
#define _FUNC(f) #f, wpa_config_parse_ ## f, NULL, NULL, NULL, NULL
#else /* NO_CONFIG_WRITE */
#define _FUNC(f) #f, wpa_config_parse_ ## f, wpa_config_write_ ## f, \
	NULL, NULL, NULL, NULL
#endif /* NO_CONFIG_WRITE */

#ifdef NO_CONFIG_WRITE
#define _INT(f) #f, wpa_config_parse_int, OFFSET(f), (void *) 0
#define _INTe(f) #f, wpa_config_parse_int, OFFSET(eap.f), (void *) 0
#else /* NO_CONFIG_WRITE */
#define _INT(f) #f, wpa_config_parse_int, wpa_config_write_int, \
	OFFSET(f), (void *) 0
#define _INTe(f) #f, wpa_config_parse_int, wpa_config_write_int, \
	OFFSET(eap.f), (void *) 0
#endif /* NO_CONFIG_WRITE */

#define FUNC(f) _FUNC(f), 0
#define FUNC_KEY(f) _FUNC(f), 1

#define INT(f) _INT(f), NULL, NULL, 0

#define DEFAULT_PROTO (WPA_PROTO_WPA | WPA_PROTO_RSN)
#define DEFAULT_KEY_MGMT (WPA_KEY_MGMT_PSK | WPA_KEY_MGMT_IEEE8021X)
#define DEFAULT_PAIRWISE (WPA_CIPHER_CCMP | WPA_CIPHER_TKIP | \
                          WPA_CIPHER_CCMP_256 | WPA_CIPHER_GCMP |\
                          WPA_CIPHER_GCMP_256)
#define DEFAULT_GROUP (WPA_CIPHER_CCMP | WPA_CIPHER_TKIP | \
                       WPA_CIPHER_CCMP_256 | WPA_CIPHER_GCMP |\
                       WPA_CIPHER_GCMP_256)

#define NUM_SSID_FIELDS ARRAY_SIZE(ssid_fields)
#endif

#if 0

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int    u32;


#ifndef _SIZE_T
#define _SIZE_T
typedef __kernel_size_t		size_t;
#endif

#ifndef BIT
#define BIT(x) (1U << (x))
#endif

#ifndef os_malloc
#define os_malloc(s) malloc((s))
#endif

#ifndef os_realloc
#define os_realloc(p, s) realloc((p), (s))
#endif

#ifndef os_free
#define os_free(p) free((p))
#endif

#ifndef os_memcpy
#define os_memcpy(d, s, n) memcpy((d), (s), (n))
#endif

#ifndef os_memmove
#define os_memmove(d, s, n) memmove((d), (s), (n))
#endif

#ifndef os_memset
#define os_memset(s, c, n) memset(s, c, n)
#endif

#ifndef os_memcmp
#define os_memcmp(s1, s2, n) memcmp((s1), (s2), (n))
#endif
#endif

#endif


