#ifndef _DEFILE_H_
#define _DEFILE_H_

typedef unsigned char  u8;

#define os_memset memset
#define os_strlcpy strncpy
#define os_memcpy memcpy


#define	IEEE80211_MAX_OPT_IE	512

#ifndef MACSTR
#define MACSTR      "%02x:%02x:%02x:%02x:%02x:%02x"
#endif
#ifndef MAC2STR
#define MAC2STR(a)  (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#endif


#define SIOCIWFIRSTPRIV	0x8BE0
#define	IEEE80211_IOCTL_SETKEY		(SIOCIWFIRSTPRIV+2)
#define IEEE80211_ADDR_LEN   6       /* size of 802.11 address */
#define IEEE80211_KEYBUF_SIZE   32 
#define IEEE80211_MICBUF_SIZE   (8+8)   /* space for both tx+rx keys */

#ifndef BIT
#define BIT(x) (1U << (x))
#endif

#define WPA_CIPHER_NONE BIT(0)
#define WPA_CIPHER_WEP40 BIT(1)
#define WPA_CIPHER_WEP104 BIT(2)
#define WPA_CIPHER_TKIP BIT(3)
#define WPA_CIPHER_CCMP BIT(4)
#define WPA_CIPHER_AES_128_CMAC BIT(5)
#define WPA_CIPHER_GCMP BIT(6)
#define WPA_CIPHER_SMS4 BIT(7)
#define WPA_CIPHER_GCMP_256 BIT(8)
#define WPA_CIPHER_CCMP_256 BIT(9)
#define WPA_CIPHER_BIP_GMAC_128 BIT(11)
#define WPA_CIPHER_BIP_GMAC_256 BIT(12)
#define WPA_CIPHER_BIP_CMAC_256 BIT(13)
#define WPA_CIPHER_GTK_NOT_USED BIT(14)

#define WPA_KEY_MGMT_IEEE8021X BIT(0)
#define WPA_KEY_MGMT_PSK BIT(1)
#define WPA_KEY_MGMT_NONE BIT(2)
#define WPA_KEY_MGMT_IEEE8021X_NO_WPA BIT(3)
#define WPA_KEY_MGMT_WPA_NONE BIT(4)
#define WPA_KEY_MGMT_FT_IEEE8021X BIT(5)
#define WPA_KEY_MGMT_FT_PSK BIT(6)
#define WPA_KEY_MGMT_IEEE8021X_SHA256 BIT(7)
#define WPA_KEY_MGMT_PSK_SHA256 BIT(8)
#define WPA_KEY_MGMT_WPS BIT(9)
#define WPA_KEY_MGMT_SAE BIT(10)
#define WPA_KEY_MGMT_FT_SAE BIT(11)
#define WPA_KEY_MGMT_WAPI_PSK BIT(12)
#define WPA_KEY_MGMT_WAPI_CERT BIT(13)
#define WPA_KEY_MGMT_CCKM BIT(14)
#define WPA_KEY_MGMT_OSEN BIT(15)
#define WPA_KEY_MGMT_IEEE8021X_SUITE_B BIT(16)
#define WPA_KEY_MGMT_IEEE8021X_SUITE_B_192 BIT(17)
#define WPA_KEY_MGMT_FILS_SHA256 BIT(18)
#define WPA_KEY_MGMT_FILS_SHA384 BIT(19)
#define WPA_KEY_MGMT_FT_FILS_SHA256 BIT(20)
#define WPA_KEY_MGMT_FT_FILS_SHA384 BIT(21)

#define WPA_PROTO_WPA BIT(0)
#define WPA_PROTO_RSN BIT(1)
#define WPA_PROTO_WAPI BIT(2)
#define WPA_PROTO_OSEN BIT(3)

#define WPA_AUTH_ALG_OPEN BIT(0)
#define WPA_AUTH_ALG_SHARED BIT(1)
#define WPA_AUTH_ALG_LEAP BIT(2)
#define WPA_AUTH_ALG_FT BIT(3)
#define WPA_AUTH_ALG_SAE BIT(4)
#define WPA_AUTH_ALG_FILS BIT(5)

enum {
	IEEE80211_PARAM_TURBO		= 1,	/* turbo mode */
	IEEE80211_PARAM_MODE		= 2,	/* phy mode (11a, 11b, etc.) */
	IEEE80211_PARAM_AUTHMODE	= 3,	/* authentication mode */
	IEEE80211_PARAM_PROTMODE	= 4,	/* 802.11g protection */
	IEEE80211_PARAM_MCASTCIPHER	= 5,	/* multicast/default cipher */
	IEEE80211_PARAM_MCASTKEYLEN	= 6,	/* multicast key length */
	IEEE80211_PARAM_UCASTCIPHERS	= 7,	/* unicast cipher suites */
	IEEE80211_PARAM_UCASTCIPHER	= 8,	/* unicast cipher */
	IEEE80211_PARAM_UCASTKEYLEN	= 9,	/* unicast key length */
	IEEE80211_PARAM_WPA		= 10,	/* WPA mode (0,1,2) */
	IEEE80211_PARAM_ROAMING		= 12,	/* roaming mode */
	IEEE80211_PARAM_PRIVACY		= 13,	/* privacy invoked */
	IEEE80211_PARAM_COUNTERMEASURES	= 14,	/* WPA/TKIP countermeasures */
	IEEE80211_PARAM_DROPUNENCRYPTED	= 15,	/* discard unencrypted frames */
	IEEE80211_PARAM_DRIVER_CAPS	= 16,	/* driver capabilities */
	IEEE80211_PARAM_MACCMD		= 17,	/* MAC ACL operation */
	IEEE80211_PARAM_WMM		= 18,	/* WMM mode (on, off) */
	IEEE80211_PARAM_HIDESSID	= 19,	/* hide SSID mode (on, off) */
	IEEE80211_PARAM_APBRIDGE	= 20,	/* AP inter-sta bridging */
	IEEE80211_PARAM_KEYMGTALGS	= 21,	/* key management algorithms */
	IEEE80211_PARAM_RSNCAPS		= 22,	/* RSN capabilities */
	IEEE80211_PARAM_INACT		= 23,	/* station inactivity timeout */
	IEEE80211_PARAM_INACT_AUTH	= 24,	/* station auth inact timeout */
	IEEE80211_PARAM_INACT_INIT	= 25,	/* station init inact timeout */
	IEEE80211_PARAM_DTIM_PERIOD	= 28,	/* DTIM period (beacons) */
	IEEE80211_PARAM_BEACON_INTERVAL	= 29,	/* beacon interval (ms) */
	IEEE80211_PARAM_DOTH		= 30,	/* 11.h is on/off */
	IEEE80211_PARAM_PWRTARGET	= 31,	/* Current Channel Pwr Constraint */
	IEEE80211_PARAM_GENREASSOC	= 32,	/* Generate a reassociation request */
	IEEE80211_PARAM_COMPRESSION	= 33,	/* compression */
	IEEE80211_PARAM_FF		= 34,	/* fast frames support */
	IEEE80211_PARAM_XR		= 35,	/* XR support */
	IEEE80211_PARAM_BURST		= 36,	/* burst mode */
	IEEE80211_PARAM_PUREG		= 37,	/* pure 11g (no 11b stations) */
	IEEE80211_PARAM_AR		= 38,	/* AR support */
	IEEE80211_PARAM_WDS		= 39,	/* Enable 4 address processing */
	IEEE80211_PARAM_BGSCAN		= 40,	/* bg scanning (on, off) */
	IEEE80211_PARAM_BGSCAN_IDLE	= 41,	/* bg scan idle threshold */
	IEEE80211_PARAM_BGSCAN_INTERVAL	= 42,	/* bg scan interval */
	IEEE80211_PARAM_MCAST_RATE	= 43,	/* Multicast Tx Rate */
	IEEE80211_PARAM_COVERAGE_CLASS	= 44,	/* coverage class */
	IEEE80211_PARAM_COUNTRY_IE	= 45,	/* enable country IE */
	IEEE80211_PARAM_SCANVALID	= 46,	/* scan cache valid threshold */
	IEEE80211_PARAM_ROAM_RSSI_11A	= 47,	/* rssi threshold in 11a */
	IEEE80211_PARAM_ROAM_RSSI_11B	= 48,	/* rssi threshold in 11b */
	IEEE80211_PARAM_ROAM_RSSI_11G	= 49,	/* rssi threshold in 11g */
	IEEE80211_PARAM_ROAM_RATE_11A	= 50,	/* tx rate threshold in 11a */
	IEEE80211_PARAM_ROAM_RATE_11B	= 51,	/* tx rate threshold in 11b */
	IEEE80211_PARAM_ROAM_RATE_11G	= 52,	/* tx rate threshold in 11g */
	IEEE80211_PARAM_UAPSDINFO	= 53,	/* value for qos info field */
	IEEE80211_PARAM_SLEEP		= 54,	/* force sleep/wake */
	IEEE80211_PARAM_QOSNULL		= 55,	/* force sleep/wake */
	IEEE80211_PARAM_PSPOLL		= 56,	/* force ps-poll generation (sta only) */
	IEEE80211_PARAM_EOSPDROP	= 57,	/* force uapsd EOSP drop (ap only) */
	IEEE80211_PARAM_MARKDFS		= 58,	/* mark a dfs interference channel when found */
	IEEE80211_PARAM_REGCLASS	= 59,	/* enable regclass ids in country IE */
	IEEE80211_PARAM_CHANBW		= 60,	/* set chan bandwidth preference */
	IEEE80211_PARAM_WMM_AGGRMODE	= 61,	/* set WMM Aggressive Mode */
	IEEE80211_PARAM_SHORTPREAMBLE	= 62, 	/* enable/disable short Preamble */
	IEEE80211_PARAM_BLOCKDFSCHAN	= 63, 	/* enable/disable use of DFS channels */
	IEEE80211_PARAM_CWM_MODE	= 64,	/* CWM mode */
	IEEE80211_PARAM_CWM_EXTOFFSET	= 65,	/* CWM extension channel offset */
	IEEE80211_PARAM_CWM_EXTPROTMODE	= 66,	/* CWM extension channel protection mode */
	IEEE80211_PARAM_CWM_EXTPROTSPACING = 67,/* CWM extension channel protection spacing */
	IEEE80211_PARAM_CWM_ENABLE	= 68,/* CWM state machine enabled */
	IEEE80211_PARAM_CWM_EXTBUSYTHRESHOLD = 69,/* CWM extension channel busy threshold */
	IEEE80211_PARAM_CWM_CHWIDTH	= 70,	/* CWM STATE: current channel width */
	IEEE80211_PARAM_SHORT_GI	= 71,	/* half GI */
	IEEE80211_PARAM_FAST_CC		= 72,	/* fast channel change */

	/*
	 * 11n A-MPDU, A-MSDU support
	 */
	IEEE80211_PARAM_AMPDU		= 73,	/* 11n a-mpdu support */
	IEEE80211_PARAM_AMPDU_LIMIT	= 74,	/* a-mpdu length limit */
	IEEE80211_PARAM_AMPDU_DENSITY	= 75,	/* a-mpdu density */
	IEEE80211_PARAM_AMPDU_SUBFRAMES	= 76,	/* a-mpdu subframe limit */
	IEEE80211_PARAM_AMSDU		= 77,	/* a-msdu support */
	IEEE80211_PARAM_AMSDU_LIMIT	= 78,	/* a-msdu length limit */

	IEEE80211_PARAM_COUNTRYCODE	= 79,	/* Get country code */
	IEEE80211_PARAM_TX_CHAINMASK	= 80,	/* Tx chain mask */
	IEEE80211_PARAM_RX_CHAINMASK	= 81,	/* Rx chain mask */
	IEEE80211_PARAM_RTSCTS_RATECODE	= 82,	/* RTS Rate code */
	IEEE80211_PARAM_HT_PROTECTION	= 83,	/* Protect traffic in HT mode */
	IEEE80211_PARAM_RESET_ONCE	= 84,	/* Force a reset */
	IEEE80211_PARAM_SETADDBAOPER	= 85,	/* Set ADDBA mode */
	IEEE80211_PARAM_TX_CHAINMASK_LEGACY = 86, /* Tx chain mask for legacy clients */
	IEEE80211_PARAM_11N_RATE	= 87,	/* Set ADDBA mode */
	IEEE80211_PARAM_11N_RETRIES	= 88,	/* Tx chain mask for legacy clients */
	IEEE80211_PARAM_DBG_LVL		= 89,	/* Debug Level for specific VAP */
	IEEE80211_PARAM_WDS_AUTODETECT	= 90,	/* Configurable Auto Detect/Delba for WDS mode */
	IEEE80211_PARAM_ATH_RADIO	= 91,	/* returns the name of the radio being used */
	IEEE80211_PARAM_IGNORE_11DBEACON = 92,	/* Don't process 11d beacon (on, off) */
	IEEE80211_PARAM_STA_FORWARD	= 93,	/* Enable client 3 addr forwarding */

	/*
	 * Mcast Enhancement support
	 */
	IEEE80211_PARAM_ME          = 94,   /* Set Mcast enhancement option: 0 disable, 1 tunneling, 2 translate  4 to disable snoop feature*/
	IEEE80211_PARAM_MEDUMP		= 95,	/* Dump the snoop table for mcast enhancement */
	IEEE80211_PARAM_MEDEBUG		= 96,	/* mcast enhancement debug level */
	IEEE80211_PARAM_ME_SNOOPLENGTH	= 97,	/* mcast snoop list length */
	IEEE80211_PARAM_ME_TIMEOUT	= 99,	/* Set Mcast enhancement timeout for STA's without traffic, in msec */
	IEEE80211_PARAM_PUREN		= 100,	/* pure 11n (no 11bg/11a stations) */
	IEEE80211_PARAM_BASICRATES	= 101,	/* Change Basic Rates */
	IEEE80211_PARAM_NO_EDGE_CH	= 102,	/* Avoid band edge channels */
	IEEE80211_PARAM_WEP_TKIP_HT	= 103,	/* Enable HT rates with WEP/TKIP encryption */
	IEEE80211_PARAM_RADIO		= 104,	/* radio on/off */
	IEEE80211_PARAM_NETWORK_SLEEP	= 105,	/* set network sleep enable/disable */
	IEEE80211_PARAM_DROPUNENC_EAPOL	= 106,

	/*
	 * Headline block removal
	 */
	IEEE80211_PARAM_HBR_TIMER	= 107,
	IEEE80211_PARAM_HBR_STATE	= 108,

	/*
	 * Unassociated power consumpion improve
	 */
	IEEE80211_PARAM_SLEEP_PRE_SCAN	= 109,
	IEEE80211_PARAM_SCAN_PRE_SLEEP	= 110,

	/* support for wapi: set auth mode and key */
	IEEE80211_PARAM_SETWAPI		= 112,
	IEEE80211_IOCTL_GREEN_AP_PS_ENABLE = 113,
	IEEE80211_IOCTL_GREEN_AP_PS_TIMEOUT = 114,
	IEEE80211_IOCTL_GREEN_AP_PS_ON_TIME = 115,
	IEEE80211_PARAM_WPS		= 116,
	IEEE80211_PARAM_RX_RATE		= 117,
	IEEE80211_PARAM_CHEXTOFFSET	= 118,
	IEEE80211_PARAM_CHSCANINIT	= 119,
	IEEE80211_PARAM_MPDU_SPACING	= 120,
	IEEE80211_PARAM_HT40_INTOLERANT	= 121,
	IEEE80211_PARAM_CHWIDTH		= 122,
	IEEE80211_PARAM_EXTAP		= 123,   /* Enable client 3 addr forwarding */
        IEEE80211_PARAM_COEXT_DISABLE    = 124,
	IEEE80211_PARAM_ME_DROPMCAST	= 125,	/* drop mcast if empty entry */
	IEEE80211_PARAM_ME_SHOWDENY	= 126,	/* show deny table for mcast enhancement */
	IEEE80211_PARAM_ME_CLEARDENY	= 127,	/* clear deny table for mcast enhancement */
	IEEE80211_PARAM_ME_ADDDENY	= 128,	/* add deny entry for mcast enhancement */
    IEEE80211_PARAM_GETIQUECONFIG = 129, /*print out the iQUE config*/
    IEEE80211_PARAM_CCMPSW_ENCDEC = 130,  /* support for ccmp s/w encrypt decrypt */

      /* Support for repeater placement */
    IEEE80211_PARAM_CUSTPROTO_ENABLE = 131,
    IEEE80211_PARAM_GPUTCALC_ENABLE  = 132,
    IEEE80211_PARAM_DEVUP            = 133,
    IEEE80211_PARAM_MACDEV           = 134,
    IEEE80211_PARAM_MACADDR1         = 135,
    IEEE80211_PARAM_MACADDR2         = 136,
    IEEE80211_PARAM_GPUTMODE         = 137,
    IEEE80211_PARAM_TXPROTOMSG       = 138,
    IEEE80211_PARAM_RXPROTOMSG       = 139,
    IEEE80211_PARAM_STATUS           = 140,
    IEEE80211_PARAM_ASSOC            = 141,
    IEEE80211_PARAM_NUMSTAS          = 142,
    IEEE80211_PARAM_STA1ROUTE        = 143,
    IEEE80211_PARAM_STA2ROUTE        = 144,
    IEEE80211_PARAM_STA3ROUTE        = 145,
    IEEE80211_PARAM_STA4ROUTE        = 146,
    IEEE80211_PARAM_PERIODIC_SCAN = 179,
#if ATH_SUPPORT_AP_WDS_COMBO
    IEEE80211_PARAM_NO_BEACON     = 180,  /* No beacon xmit on VAP */
#endif
    IEEE80211_PARAM_VAP_COUNTRY_IE   = 181, /* 802.11d country ie per vap */
    IEEE80211_PARAM_VAP_DOTH         = 182, /* 802.11h per vap */
    IEEE80211_PARAM_STA_QUICKKICKOUT = 183, /* station quick kick out */
    IEEE80211_PARAM_AUTO_ASSOC       = 184,
    IEEE80211_PARAM_RXBUF_LIFETIME   = 185, /* lifetime of reycled rx buffers */
    IEEE80211_PARAM_2G_CSA           = 186, /* 2.4 GHz CSA is on/off */
    IEEE80211_PARAM_WAPIREKEY_USK = 187,
    IEEE80211_PARAM_WAPIREKEY_MSK = 188,
    IEEE80211_PARAM_WAPIREKEY_UPDATE = 189,
#if ATH_SUPPORT_IQUE
    IEEE80211_PARAM_RC_VIVO          = 190, /* Use separate rate control algorithm for VI/VO queues */
#endif
    IEEE80211_PARAM_CLR_APPOPT_IE    = 191,  /* Clear Cached App/OptIE */
    IEEE80211_PARAM_SW_WOW           = 192,   /* wow by sw */
    IEEE80211_PARAM_QUIET_PERIOD    = 193,
    IEEE80211_PARAM_QBSS_LOAD       = 194,
    IEEE80211_PARAM_RRM_CAP         = 195,
    IEEE80211_PARAM_WNM_CAP         = 196,
#if UMAC_SUPPORT_WDS
    IEEE80211_PARAM_ADD_WDS_ADDR    = 197,  /* add wds addr */
#endif
#ifdef QCA_PARTNER_PLATFORM
    IEEE80211_PARAM_PLTFRM_PRIVATE = 198, /* platfrom's private ioctl*/
#endif

#if UMAC_SUPPORT_VI_DBG
    /* Support for Video Debug */
    IEEE80211_PARAM_DBG_CFG            = 199,
    IEEE80211_PARAM_DBG_NUM_STREAMS    = 200,
    IEEE80211_PARAM_STREAM_NUM         = 201,
    IEEE80211_PARAM_DBG_NUM_MARKERS    = 202,
    IEEE80211_PARAM_MARKER_NUM         = 203,
    IEEE80211_PARAM_MARKER_OFFSET_SIZE = 204,
    IEEE80211_PARAM_MARKER_MATCH       = 205,
    IEEE80211_PARAM_RXSEQ_OFFSET_SIZE  = 206,
    IEEE80211_PARAM_RX_SEQ_RSHIFT      = 207,
    IEEE80211_PARAM_RX_SEQ_MAX         = 208,
    IEEE80211_PARAM_RX_SEQ_DROP        = 209,
    IEEE80211_PARAM_TIME_OFFSET_SIZE   = 210,
    IEEE80211_PARAM_RESTART            = 211,
    IEEE80211_PARAM_RXDROP_STATUS      = 212,
#endif
#if ATH_SUPPORT_IBSS_DFS
    IEEE80211_PARAM_IBSS_DFS_PARAM     = 225,
#endif
#if ATH_SUPPORT_IBSS_NETLINK_NOTIFICATION
    IEEE80211_PARAM_IBSS_SET_RSSI_CLASS     = 237,
    IEEE80211_PARAM_IBSS_START_RSSI_MONITOR = 238,
    IEEE80211_PARAM_IBSS_RSSI_HYSTERESIS    = 239,
#endif
#ifdef ATH_SUPPORT_TxBF
    IEEE80211_PARAM_TXBF_AUTO_CVUPDATE = 240,       /* Auto CV update enable*/
    IEEE80211_PARAM_TXBF_CVUPDATE_PER = 241,        /* per theshold to initial CV update*/
#endif
    IEEE80211_PARAM_MAXSTA              = 242,
    IEEE80211_PARAM_RRM_STATS               =243,
    IEEE80211_PARAM_RRM_SLWINDOW            =244,
    IEEE80211_PARAM_MFP_TEST    = 245,
    IEEE80211_PARAM_SCAN_BAND   = 246,                /* only scan channels of requested band */
#if ATH_SUPPORT_FLOWMAC_MODULE
    IEEE80211_PARAM_FLOWMAC            = 247, /* flowmac enable/disable ath0*/
#endif
    IEEE80211_PARAM_STA_PWR_SET_PSPOLL      = 255,  /* Set ips_use_pspoll flag for STA */
    IEEE80211_PARAM_NO_STOP_DISASSOC        = 256,  /* Do not send disassociation frame on stopping vap */
#if UMAC_SUPPORT_IBSS
    IEEE80211_PARAM_IBSS_CREATE_DISABLE = 257,      /* if set, it prevents IBSS creation */
#endif
#if ATH_SUPPORT_WIFIPOS
    IEEE80211_PARAM_WIFIPOS_TXCORRECTION = 258,      /* Set/Get TxCorrection */
    IEEE80211_PARAM_WIFIPOS_RXCORRECTION = 259,      /* Set/Get RxCorrection */
#endif
#if UMAC_SUPPORT_CHANUTIL_MEASUREMENT
    IEEE80211_PARAM_CHAN_UTIL_ENAB      = 260,
    IEEE80211_PARAM_CHAN_UTIL           = 261,      /* Get Channel Utilization value (scale: 0 - 255) */
#endif /* UMAC_SUPPORT_CHANUTIL_MEASUREMENT */
    IEEE80211_PARAM_DBG_LVL_HIGH        = 262, /* Debug Level for specific VAP (upper 32 bits) */
    IEEE80211_PARAM_PROXYARP_CAP        = 263, /* Enable WNM Proxy ARP feature */
    IEEE80211_PARAM_DGAF_DISABLE        = 264, /* Hotspot 2.0 DGAF Disable feature */
    IEEE80211_PARAM_L2TIF_CAP           = 265, /* Hotspot 2.0 L2 Traffic Inspection and Filtering */
    IEEE80211_PARAM_WEATHER_RADAR_CHANNEL = 266, /* weather radar channel selection is bypassed */
    IEEE80211_PARAM_SEND_DEAUTH           = 267,/* for sending deauth while doing interface down*/
    IEEE80211_PARAM_WEP_KEYCACHE          = 268,/* wepkeys mustbe in first fourslots in Keycache*/
#if ATH_SUPPORT_WPA_SUPPLICANT_CHECK_TIME
    IEEE80211_PARAM_REJOINT_ATTEMP_TIME   = 269, /* Set the Rejoint time */
#endif
    IEEE80211_PARAM_WNM_SLEEP           = 270,      /* WNM-Sleep Mode */
    IEEE80211_PARAM_WNM_BSS_CAP         = 271,
    IEEE80211_PARAM_WNM_TFS_CAP         = 272,
    IEEE80211_PARAM_WNM_TIM_CAP         = 273,
    IEEE80211_PARAM_WNM_SLEEP_CAP       = 274,
    IEEE80211_PARAM_WNM_FMS_CAP         = 275,
    IEEE80211_PARAM_RRM_DEBUG           = 276, /* RRM debugging parameter */
    IEEE80211_PARAM_SET_TXPWRADJUST     = 277,
    IEEE80211_PARAM_TXRX_DBG              = 278,    /* show txrx debug info */
    IEEE80211_PARAM_VHT_MCS               = 279,    /* VHT MCS set */
    IEEE80211_PARAM_TXRX_FW_STATS         = 280,    /* single FW stat */
    IEEE80211_PARAM_TXRX_FW_MSTATS        = 281,    /* multiple FW stats */
    IEEE80211_PARAM_NSS                   = 282,    /* Number of Spatial Streams */
    IEEE80211_PARAM_LDPC                  = 283,    /* Support LDPC */
    IEEE80211_PARAM_TX_STBC               = 284,    /* Support TX STBC */
    IEEE80211_PARAM_RX_STBC               = 285,    /* Support RX STBC */
    IEEE80211_PARAM_APONLY                  = 293,
    IEEE80211_PARAM_TXRX_FW_STATS_RESET     = 294,
    IEEE80211_PARAM_TX_PPDU_LOG_CFG         = 295,  /* tx PPDU log cfg params */
    IEEE80211_PARAM_OPMODE_NOTIFY           = 296,  /* Op Mode Notification */
    IEEE80211_PARAM_NOPBN                   = 297, /* don't send push button notification */
    IEEE80211_PARAM_DFS_CACTIMEOUT          = 298, /* override CAC timeout */
    IEEE80211_PARAM_ENABLE_RTSCTS           = 299, /* Enable/disable RTS-CTS */

    IEEE80211_PARAM_MAX_AMPDU               = 300,   /* Set/Get rx AMPDU exponent/shift */
    IEEE80211_PARAM_VHT_MAX_AMPDU           = 301,   /* Set/Get rx VHT AMPDU exponent/shift */
    IEEE80211_PARAM_BCAST_RATE              = 302,   /* Setting Bcast DATA rate */
    IEEE80211_PARAM_PARENT_IFINDEX          = 304,   /* parent net_device ifindex for this VAP */
#if WDS_VENDOR_EXTENSION
    IEEE80211_PARAM_WDS_RX_POLICY           = 305,  /* Set/Get WDS rx filter policy for vendor specific WDS */
#endif
    IEEE80211_PARAM_ENABLE_OL_STATS         = 306,   /*Enables/Disables the
                                                        stats in the Host and in the FW */
    IEEE80211_IOCTL_GREEN_AP_ENABLE_PRINT   = 307,  /* Enable/Disable Green-AP debug prints */
    IEEE80211_PARAM_RC_NUM_RETRIES          = 308,
    IEEE80211_PARAM_GET_ACS                 = 309,/* to get status of acs */
    IEEE80211_PARAM_GET_CAC                 = 310,/* to get status of CAC period */
    IEEE80211_PARAM_EXT_IFACEUP_ACS         = 311,  /* Enable external auto channel selection entity
                                                       at VAP init time */
    IEEE80211_PARAM_ONETXCHAIN              = 312,  /* force to tx with one chain for legacy client */
    IEEE80211_PARAM_DFSDOMAIN               = 313,  /* Get DFS Domain */
    IEEE80211_PARAM_SCAN_CHAN_EVENT         = 314,  /* Enable delivery of Scan Channel Events during
                                                       802.11 scans (11ac offload, and IEEE80211_M_HOSTAP
                                                       mode only). */
    IEEE80211_PARAM_DESIRED_CHANNEL         = 315,  /* Get desired channel corresponding to desired
                                                       PHY mode */
    IEEE80211_PARAM_DESIRED_PHYMODE         = 316,  /* Get desired PHY mode */
    IEEE80211_PARAM_SEND_ADDITIONAL_IES     = 317,  /* Control sending of additional IEs to host */
    IEEE80211_PARAM_START_ACS_REPORT        = 318,  /* to start acs scan report */
    IEEE80211_PARAM_MIN_DWELL_ACS_REPORT    = 319,  /* min dwell time for  acs scan report */
    IEEE80211_PARAM_MAX_DWELL_ACS_REPORT    = 320,  /* max dwell time for  acs scan report */
    IEEE80211_PARAM_ACS_CH_HOP_LONG_DUR     = 321,  /* channel long duration timer used in acs */
    IEEE80211_PARAM_ACS_CH_HOP_NO_HOP_DUR   = 322,  /* No hopping timer used in acs */
    IEEE80211_PARAM_ACS_CH_HOP_CNT_WIN_DUR  = 323,  /* counter window timer used in acs */
    IEEE80211_PARAM_ACS_CH_HOP_NOISE_TH     = 324,  /* Noise threshold used in acs channel hopping */
    IEEE80211_PARAM_ACS_CH_HOP_CNT_TH       = 325,  /* counter threshold used in acs channel hopping */
    IEEE80211_PARAM_ACS_ENABLE_CH_HOP       = 326,  /* Enable/Disable acs channel hopping */
    IEEE80211_PARAM_SET_CABQ_MAXDUR         = 327,  /* set the max tx percentage for cabq */
    IEEE80211_PARAM_256QAM_2G               = 328,  /* 2.4 GHz 256 QAM support */
    IEEE80211_PARAM_MAX_SCANENTRY           = 330,  /* MAX scan entry */
    IEEE80211_PARAM_SCANENTRY_TIMEOUT       = 331,  /* Scan entry timeout value */
    IEEE80211_PARAM_PURE11AC                = 332,  /* pure 11ac(no 11bg/11a/11n stations) */
#if UMAC_VOW_DEBUG
    IEEE80211_PARAM_VOW_DBG_ENABLE  = 333,  /*Enable VoW debug*/
#endif
    IEEE80211_PARAM_SCAN_MIN_DWELL          = 334,  /* MIN dwell time to be used during scan */
    IEEE80211_PARAM_SCAN_MAX_DWELL          = 335,  /* MAX dwell time to be used during scan */
    IEEE80211_PARAM_BANDWIDTH               = 336,
    IEEE80211_PARAM_FREQ_BAND               = 337,
    IEEE80211_PARAM_EXTCHAN                 = 338,
    IEEE80211_PARAM_MCS                     = 339,
    IEEE80211_PARAM_CHAN_NOISE              = 340,
    IEEE80211_PARAM_VHT_SGIMASK             = 341,   /* Set VHT SGI MASK */
    IEEE80211_PARAM_VHT80_RATEMASK          = 342,   /* Set VHT80 Auto Rate MASK */
#if ATH_PERF_PWR_OFFLOAD
    IEEE80211_PARAM_VAP_TX_ENCAP_TYPE       = 343,
    IEEE80211_PARAM_VAP_RX_DECAP_TYPE       = 344,
#endif /* ATH_PERF_PWR_OFFLOAD */
#if (HOST_SW_TSO_ENABLE || HOST_SW_TSO_SG_ENABLE)
    IEEE80211_PARAM_TSO_STATS               = 345, /* Get TSO Stats */
    IEEE80211_PARAM_TSO_STATS_RESET         = 346, /* Reset TSO Stats */
#endif /* HOST_SW_TSO_ENABLE || HOST_SW_TSO_SG_ENABLE */
#if HOST_SW_LRO_ENABLE
    IEEE80211_PARAM_LRO_STATS               = 347, /* Get LRO Stats */
    IEEE80211_PARAM_LRO_STATS_RESET         = 348, /* Reset LRO Stats */
#endif /* HOST_SW_LRO_ENABLE */
#if RX_CHECKSUM_OFFLOAD
    IEEE80211_PARAM_RX_CKSUM_ERR_STATS      = 349, /* Get RX CKSUM Err Stats */
    IEEE80211_PARAM_RX_CKSUM_ERR_RESET      = 350, /* Reset RX CKSUM Err Stats */
#endif /* RX_CHECKSUM_OFFLOAD */

    IEEE80211_PARAM_VHT_STS_CAP             = 351,
    IEEE80211_PARAM_VHT_SOUNDING_DIM        = 352,
    IEEE80211_PARAM_VHT_SUBFEE              = 353,   /* set VHT SU beamformee capability */
    IEEE80211_PARAM_VHT_MUBFEE              = 354,   /* set VHT MU beamformee capability */
    IEEE80211_PARAM_VHT_SUBFER              = 355,   /* set VHT SU beamformer capability */
    IEEE80211_PARAM_VHT_MUBFER              = 356,   /* set VHT MU beamformer capability */
    IEEE80211_PARAM_IMPLICITBF              = 357,
    IEEE80211_PARAM_SEND_WOWPKT             = 358, /* Send Wake-On-Wireless packet */
    IEEE80211_PARAM_STA_FIXED_RATE          = 359, /* set/get fixed rate for associated sta on AP */
    IEEE80211_PARAM_11NG_VHT_INTEROP        = 360,  /* 2.4ng Vht Interop */
#if HOST_SW_SG_ENABLE
    IEEE80211_PARAM_SG_STATS                = 361, /* Get SG Stats */
    IEEE80211_PARAM_SG_STATS_RESET          = 362, /* Reset SG Stats */
#endif /* HOST_SW_SG_ENABLE */
    IEEE80211_PARAM_SPLITMAC                = 363,
    IEEE80211_PARAM_SHORT_SLOT              = 364,   /* Set short slot time */
    IEEE80211_PARAM_SET_ERP                 = 365,   /* Set ERP protection mode  */
    IEEE80211_PARAM_SESSION_TIMEOUT         = 366,   /* STA's session time */
#if ATH_PERF_PWR_OFFLOAD && QCA_SUPPORT_RAWMODE_PKT_SIMULATION
    IEEE80211_PARAM_RAWMODE_SIM_TXAGGR      = 367,   /* Enable/disable raw mode simulation
                                                        Tx A-MSDU aggregation */
    IEEE80211_PARAM_RAWMODE_PKT_SIM_STATS   = 368,   /* Get Raw mode packet simulation stats. */
    IEEE80211_PARAM_CLR_RAWMODE_PKT_SIM_STATS = 369, /* Clear Raw mode packet simulation stats. */
    IEEE80211_PARAM_RAWMODE_SIM_DEBUG       = 370,   /* Enable/disable raw mode simulation debug */
#endif /* ATH_PERF_PWR_OFFLOAD && QCA_SUPPORT_RAWMODE_PKT_SIMULATION */
    IEEE80211_PARAM_PROXY_STA               = 371,   /* set/get ProxySTA */
    IEEE80211_PARAM_BW_NSS_RATEMASK         = 372,   /* Set ratemask with specific Bandwidth and NSS  */
    IEEE80211_PARAM_RX_SIGNAL_DBM           = 373,  /*get rx signal strength in dBm*/
    IEEE80211_PARAM_VHT_TX_MCSMAP           = 374,   /* Set VHT TX MCS MAP */
    IEEE80211_PARAM_VHT_RX_MCSMAP           = 375,   /* Set VHT RX MCS MAP */
    IEEE80211_PARAM_WNM_SMENTER             = 376,
    IEEE80211_PARAM_WNM_SMEXIT              = 377,
    IEEE80211_PARAM_HC_BSSLOAD              = 378,
    IEEE80211_PARAM_OSEN                    = 379,
#if QCA_AIRTIME_FAIRNESS
    IEEE80211_PARAM_ATF_OPT                 = 380,   /* set airtime feature */
    IEEE80211_PARAM_ATF_PER_UNIT            = 381,
#endif
    IEEE80211_PARAM_TX_MIN_POWER            = 382, /* Get min tx power */
    IEEE80211_PARAM_TX_MAX_POWER            = 383, /* Get max tx power */
    IEEE80211_PARAM_MGMT_RATE               = 384, /* Set mgmt rate, will set mcast/bcast/ucast to same rate*/
    IEEE80211_PARAM_NO_VAP_RESET            = 385, /* Disable the VAP reset in NSS */
    IEEE80211_PARAM_STA_COUNT               = 386, /* TO get number of station associated*/
#if ATH_SSID_STEERING
    IEEE80211_PARAM_VAP_SSID_CONFIG         = 387, /* Vap configuration  */
#endif
#if ATH_SUPPORT_DSCP_OVERRIDE
    IEEE80211_PARAM_DSCP_OVERRIDE           = 388,
    IEEE80211_PARAM_DSCP_TID_MAP            = 389,
#endif
    IEEE80211_PARAM_RX_FILTER_MONITOR       = 390,
    IEEE80211_PARAM_SECOND_CENTER_FREQ      = 391,
    IEEE80211_PARAM_STRICT_BW               = 392,  /* BW restriction in pure 11ac */
    IEEE80211_PARAM_ADD_LOCAL_PEER          = 393,
    IEEE80211_PARAM_SET_MHDR                = 394,
    IEEE80211_PARAM_ALLOW_DATA              = 395,
    IEEE80211_PARAM_SET_MESHDBG             = 396,
    IEEE80211_PARAM_RTT_ENABLE              = 397,
    IEEE80211_PARAM_LCI_ENABLE              = 398,
    IEEE80211_PARAM_VAP_ENHIND              = 399, /* Independent VAP mode for Repeater and AP-STA config */
    IEEE80211_PARAM_VAP_PAUSE_SCAN          = 400, /* Pause VAP mode for scanning */
    IEEE80211_PARAM_EXT_ACS_IN_PROGRESS     = 401, /* Whether external auto channel selection is in
                                                    progress */
    IEEE80211_PARAM_AMPDU_DENSITY_OVERRIDE  = 402,  /* a-mpdu density override */
    IEEE80211_PARAM_SMART_MESH_CONFIG       = 403,  /* smart MESH configuration */
    IEEE80211_DISABLE_BCN_BW_NSS_MAP        = 404, /* To set & get Bandwidth-NSS mapping in beacon as vendor specific IE*/
    IEEE80211_DISABLE_STA_BWNSS_ADV         = 405, /* To disable all Bandwidth-NSS mapping feature in STA mode*/
    IEEE80211_PARAM_MIXED_MODE              = 406, /* In case of STA, this tells whether the AP we are associated
                                                      to supports TKIP alongwith AES */
    IEEE80211_PARAM_RX_FILTER_NEIGHBOUR_PEERS_MONITOR = 407,  /* filter out /drop invalid peers packet to upper stack */
#if ATH_DATA_RX_INFO_EN
    IEEE80211_PARAM_RXINFO_PERPKT          = 408,  /* update rx info per pkt */
#endif
    IEEE80211_PARAM_WHC_APINFO_WDS          = 415, /* Whether associated AP supports WDS
                                                      (as determined from the vendor IE) */
    IEEE80211_PARAM_WHC_APINFO_ROOT_DIST    = 416, /* Distance from the root AP (in hops);
                                                      only valid if the WDS flag is set
                                                      based on the param above */
    IEEE80211_PARAM_ATH_SUPPORT_VLAN        = 417,
    IEEE80211_PARAM_CONFIG_ASSOC_WAR_160W   = 418, /* Configure association WAR for 160 MHz width (i.e.
                                                      160/80+80 MHz modes). Some STAs may have an issue
                                                      associating with us if we advertise 160/80+80 MHz related
                                                      capabilities in probe response/association response.
                                                      Hence this WAR suppresses 160/80+80 MHz related
                                                      information in probe responses, and association responses
                                                      for such STAs.
                                                      Starting from LSB
                                                      First bit set        = Default WAR behavior (VHT_OP modified)
                                                      First+second bit set = (VHT_OP+ VHT_CAP modified)
                                                      No bit set (default) = WAR disabled
                                                     */
#if DBG_LVL_MAC_FILTERING
    IEEE80211_PARAM_DBG_LVL_MAC             = 419, /* Enable/disable mac based filtering for debug logs */
#endif
#if QCA_AIRTIME_FAIRNESS
    IEEE80211_PARAM_ATF_TXBUF_MAX           = 420,
    IEEE80211_PARAM_ATF_TXBUF_MIN           = 421,
    IEEE80211_PARAM_ATF_TXBUF_SHARE         = 422, /* For ATF UDP */
    IEEE80211_PARAM_ATF_MAX_CLIENT          = 423, /* Support of ATF+non-ATF clients */
    IEEE80211_PARAM_ATF_SSID_GROUP          = 424, /* Support to enable/disable SSID grouping */
#endif
    IEEE80211_PARAM_11N_TX_AMSDU            = 425, /* Enable/Disable HT Tx AMSDU only */
    IEEE80211_PARAM_BSS_CHAN_INFO           = 426,
    IEEE80211_PARAM_LCR_ENABLE              = 427,
    IEEE80211_PARAM_WHC_APINFO_SON          = 428, /* Whether associated AP supports SON mode
                                                      (as determined from the vendor IE) */
    IEEE80211_PARAM_SON                     = 429, /* Mark/query AP as SON enabled */
    IEEE80211_PARAM_CTSPROT_DTIM_BCN        = 430, /* Enable/Disable CTS2SELF protection for DTIM Beacons */
    IEEE80211_PARAM_RAWMODE_PKT_SIM         = 431, /* Enable/Disable RAWMODE_PKT_SIM*/
    IEEE80211_PARAM_CONFIG_RAW_DWEP_IND     = 432, /* Enable/disable indication to WLAN driver that
                                                      dynamic WEP is being used in RAW mode. If the indication
                                                      is enabled and we are in RAW mode, we plumb a dummy key for
                                                      each of the keys corresponding to WEP cipher
                                                   */
#if ATH_GEN_RANDOMNESS
    IEEE80211_PARAM_RANDOMGEN_MODE           = 433,
#endif

   IEEE80211_PARAM_CUSTOM_CHAN_LIST         = 434,
#if UMAC_SUPPORT_ACFG
    IEEE80211_PARAM_DIAG_WARN_THRESHOLD     = 435,
    IEEE80211_PARAM_DIAG_ERR_THRESHOLD      = 436,
#endif
    IEEE80211_PARAM_MBO                           = 437,     /*  Enable MBO */
    IEEE80211_PARAM_MBO_CAP                       = 438,     /*  Enable MBO capability */
    IEEE80211_PARAM_MBO_ASSOC_DISALLOW            = 439,     /*  MBO  reason code for assoc disallow attribute */
    IEEE80211_PARAM_MBO_CELLULAR_PREFERENCE       = 440,     /*  MBO cellular preference */
    IEEE80211_PARAM_MBO_TRANSITION_REASON         = 441,     /*  MBO Tansition reason */
    IEEE80211_PARAM_MBO_ASSOC_RETRY_DELAY         = 442,     /*  MBO  assoc retry delay */
#if ATH_SUPPORT_DSCP_OVERRIDE
    IEEE80211_PARAM_VAP_DSCP_PRIORITY        = 443,  /* VAP Based DSCP - Vap priority */
#endif
    IEEE80211_PARAM_TXRX_VAP_STATS           = 444,
    IEEE80211_PARAM_CONFIG_REV_SIG_160W      = 445, /* Enable/Disable revised signalling for 160/80+80 MHz */
    IEEE80211_PARAM_DISABLE_SELECTIVE_HTMCS_FOR_VAP = 446, /* Enable/Disable selective HT-MCS for this vap. */
    IEEE80211_PARAM_CONFIGURE_SELECTIVE_VHTMCS_FOR_VAP = 447, /* Enable/Disable selective VHT-MCS for this vap. */
    IEEE80211_PARAM_RDG_ENABLE              = 448,
    IEEE80211_PARAM_DFS_SUPPORT             = 449,
    IEEE80211_PARAM_DFS_ENABLE              = 450,
    IEEE80211_PARAM_ACS_SUPPORT             = 451,
    IEEE80211_PARAM_SSID_STATUS             = 452,
    IEEE80211_PARAM_DL_QUEUE_PRIORITY_SUPPORT = 453,
    IEEE80211_PARAM_CLEAR_MIN_MAX_RSSI        = 454,
    IEEE80211_PARAM_CLEAR_QOS            = 455,
#if QCA_AIRTIME_FAIRNESS
    IEEE80211_PARAM_ATF_OVERRIDE_AIRTIME_TPUT = 456, /* Override the airtime estimated */
#endif
#if MESH_MODE_SUPPORT
    IEEE80211_PARAM_MESH_CAPABILITIES      = 457, /* For providing Mesh vap capabilities */
#endif
#if UMAC_SUPPORT_ACL
    IEEE80211_PARAM_CONFIG_ASSOC_DENIAL_NOTIFY = 458,  /* Enable/disable assoc denial notification to userspace */
    IEEE80211_PARAM_ADD_MAC_LIST_SEC = 459, /* To check if the mac address is to added in secondary ACL list */
    IEEE80211_PARAM_GET_MAC_LIST_SEC = 460, /* To get the mac addresses from the secondary ACL list */
    IEEE80211_PARAM_DEL_MAC_LIST_SEC = 461, /* To delete the given mac address from the secondary ACL list */
    IEEE80211_PARAM_MACCMD_SEC = 462, /* To set/get the acl policy of the secondary ACL list */
#endif /* UMAC_SUPPORT_ACL */
    IEEE80211_PARAM_UMAC_VERBOSE_LVL           = 463, /* verbose level for UMAC specific debug */
    IEEE80211_PARAM_VAP_TXRX_FW_STATS          = 464, /* Get per VAP MU-MIMO stats */
    IEEE80211_PARAM_VAP_TXRX_FW_STATS_RESET    = 465, /* Reset per VAp MU-MIMO stats */
    IEEE80211_PARAM_PEER_TX_MU_BLACKLIST_COUNT = 466, /* Get number of times a peer has been blacklisted due to sounding failures */
    IEEE80211_PARAM_PEER_TX_COUNT              = 467, /* Get count of MU MIMO tx to a peer */
    IEEE80211_PARAM_PEER_MUMIMO_TX_COUNT_RESET = 468, /* Reset count of MU MIMO tx to a peer */
    IEEE80211_PARAM_PEER_POSITION              = 469, /* Get peer position in MU group */
#if QCA_AIRTIME_FAIRNESS
    IEEE80211_PARAM_ATF_SSID_SCHED_POLICY    = 470, /* support to set per ssid atf sched policy, 0-fair 1-strict */
#endif
    IEEE80211_PARAM_CONNECTION_SM_STATE        = 471, /* Get the current state of the connectionm SM */
#if MESH_MODE_SUPPORT
    IEEE80211_PARAM_CONFIG_MGMT_TX_FOR_MESH    = 472,
    IEEE80211_PARAM_CONFIG_RX_MESH_FILTER      = 473,
#endif
    IEEE80211_PARAM_TRAFFIC_STATS              = 474,   /* Enable/disable the measurement of traffic statistics */
    IEEE80211_PARAM_TRAFFIC_RATE               = 475,   /* set the traffic rate, the rate at which the received signal statistics are be measured */
    IEEE80211_PARAM_TRAFFIC_INTERVAL           = 476,   /* set the traffic interval,the time till which the received signal statistics are to be measured */
    IEEE80211_PARAM_WATERMARK_THRESHOLD        = 477,
    IEEE80211_PARAM_WATERMARK_REACHED          = 478,
    IEEE80211_PARAM_ASSOC_REACHED              = 479,
    IEEE80211_PARAM_DISABLE_SELECTIVE_LEGACY_RATE_FOR_VAP = 480,      /* Enable/Disable selective Legacy Rates for this vap. */
    IEEE80211_PARAM_RTSCTS_RATE                = 481,   /* Set rts and cts rate*/
    IEEE80211_PARAM_REPT_MULTI_SPECIAL         = 482,
    IEEE80211_PARAM_VSP_ENABLE                 = 483,   /* Video Stream Protection */
    IEEE80211_PARAM_ENABLE_VENDOR_IE           = 484,    /* Enable/ disable Vendor ie advertise in Beacon/ proberesponse*/
    IEEE80211_PARAM_WHC_APINFO_SFACTOR         = 485,  /* Set Scaling factor for best uplink selection algorithm */
    IEEE80211_PARAM_WHC_APINFO_BSSID           = 486,  /* Get the best uplink BSSID for scan entries */
    IEEE80211_PARAM_WHC_APINFO_RATE            = 487,  /* Get the current uplink data rate(estimate) */
    IEEE80211_PARAM_CONFIG_MON_DECODER         = 488,  /* Monitor VAP decoder format radiotap/prism */
    IEEE80211_PARAM_DYN_BW_RTS                 = 489,   /* Enable/Disable the dynamic bandwidth RTS */
    IEEE80211_PARAM_CONFIG_MU_CAP_TIMER        = 490,  /* Set/Get timer period in seconds(1 to 300) for de-assoc dedicated client when
                                                       mu-cap client joins/leaves */
    IEEE80211_PARAM_CONFIG_MU_CAP_WAR          = 491,   /* Enable/Disable Mu Cap WAR function */
    IEEE80211_PARAM_CONFIG_BSSID               = 492,  /* Configure hidden ssid AP's bssid */
    IEEE80211_PARAM_CONFIG_NSTSCAP_WAR         = 493,  /* Enable/Disable NSTS CAP WAR */
    IEEE80211_PARAM_WHC_APINFO_CAP_BSSID       = 494,   /* get the CAP BSSID from scan entries */
    IEEE80211_PARAM_BEACON_RATE_FOR_VAP        = 495,      /*Configure beacon rate to user provided rate*/
    IEEE80211_PARAM_CHANNEL_SWITCH_MODE        = 496,   /* channel switch mode to be used in CSA and ECSA IE*/
    IEEE80211_PARAM_ENABLE_ECSA_IE             = 497,   /* ECSA IE  enable/disable*/
    IEEE80211_PARAM_ECSA_OPCLASS               = 498,   /* opClass to be announced in ECSA IE */
#if DYNAMIC_BEACON_SUPPORT
    IEEE80211_PARAM_DBEACON_EN                 = 499, /* Enable/disable the dynamic beacon feature */
    IEEE80211_PARAM_DBEACON_RSSI_THR           = 500, /* Set/Get the rssi threshold */
    IEEE80211_PARAM_DBEACON_TIMEOUT            = 501, /* Set/Get the timeout of timer */
#endif
    IEEE80211_PARAM_TXPOW_MGMT                 = 502,   /* set/get the tx power per vap */
    IEEE80211_PARAM_CONFIG_TX_CAPTURE          = 503, /* Configure pkt capture in Tx direction */
    IEEE80211_PARAM_GET_CONFIG_BSSID           = 504, /* get configured hidden ssid AP's bssid */
    IEEE80211_PARAM_OCE                        = 505,  /* Enable OCE */
    IEEE80211_PARAM_OCE_ASSOC_REJECT           = 506,  /* Enable OCE RSSI-based assoc reject */
    IEEE80211_PARAM_OCE_ASSOC_MIN_RSSI         = 507,  /* Min RSSI for assoc accept */
    IEEE80211_PARAM_OCE_ASSOC_RETRY_DELAY      = 508,  /* Retry delay for subsequent (re-)assoc */
    IEEE80211_PARAM_OCE_WAN_METRICS            = 509,  /* Enable OCE reduced WAN metrics */
    IEEE80211_PARAM_BACKHAUL                   = 510,
    IEEE80211_PARAM_WHC_APINFO_BEST_UPLINK_OTHERBAND_BSSID = 511, /* Get the best otherband uplink BSSID */
    IEEE80211_PARAM_WHC_APINFO_OTHERBAND_UPLINK_BSSID = 512, /* Get the current otherband uplink BSSID from scan entry */
    IEEE80211_PARAM_WHC_APINFO_OTHERBAND_BSSID = 513, /* Set the otherband BSSID for AP vap */
    IEEE80211_PARAM_EXT_NSS_CAPABLE            = 514, /* EXT NSS Capable */
    IEEE80211_PARAM_SEND_PROBE_REQ             = 515, /* Send bcast probe request with current ssid */
#if ATH_SUPPORT_NR_SYNC
    IEEE80211_PARAM_NR_SHARE_RADIO_FLAG        = 516,   /* The mask to indicate which radio the NR information shares across */
#endif
    IEEE80211_PARAM_WHC_APINFO_UPLINK_RATE     = 517,  /* Get the current uplink rate */
#if QCN_IE
    IEEE80211_PARAM_BCAST_PROBE_RESPONSE_DELAY = 518, /* set/get the delay for holding the broadcast
                                                         probe response (in ms) */
    IEEE80211_PARAM_BCAST_PROBE_RESPONSE_LATENCY_COMPENSATION = 519, /* set/get latency for the RTT made by the broadcast
                                                                        probe response(in ms) */
    IEEE80211_PARAM_BCAST_PROBE_RESPONSE_STATS = 520, /* Get the broadcast probe response stats */
    IEEE80211_PARAM_BCAST_PROBE_RESPONSE_ENABLE = 521, /* If set, enables the broadcast probe response feature */
    IEEE80211_PARAM_BCAST_PROBE_RESPONSE_STATS_CLEAR = 522, /* Clear the broadcast probe response stats */
    IEEE80211_PARAM_BEACON_LATENCY_COMPENSATION = 523, /* Set/get the beacon latency between driver and firmware */
#endif
    IEEE80211_PARAM_CSL_SUPPORT                = 524,  /* CSL Support */
    IEEE80211_PARAM_SIFS_TRIGGER               = 525,  /* get/set sifs trigger interval per vdev */
    IEEE80211_PARAM_CONFIG_TX_CAPTURE_DA       = 526,  /* Enable the Tx capture for DA radios, if monitor VAP is available */
    IEEE80211_PARAM_EXT_NSS_SUPPORT            = 527,  /* EXT NSS Support */
    IEEE80211_PARAM_RX_FILTER_SMART_MONITOR    = 528,  /* Get per vap smart monitor stats */
    IEEE80211_PARAM_DISABLE_CABQ               = 529,  /* Disable multicast buffer when STA is PS */
    IEEE80211_PARAM_WHC_CAP_RSSI               = 530,  /* Set/Get the CAP RSSI threshold for best uplink selection */
    IEEE80211_PARAM_WHC_CURRENT_CAP_RSSI       = 531,  /* Get the current CAP RSSI from scan entrie */
    IEEE80211_PARAM_ENABLE_FILS                = 532,  /* Enable/disable FILS */
    IEEE80211_PARAM_SIFS_TRIGGER_RATE          = 533,  /* get/set sifs trigger rate per vdev */
    IEEE80211_PARAM_RX_SMART_MONITOR_RSSI      = 534,  /* Get smart monitor rssi */
    IEEE80211_PARAM_GET_CONFIG_REJECT_MGMT_FRAME     = 535,  /* get the list of addr's for which mgmt pkts need to be rejected */
    IEEE80211_PARAM_ADD_MAC_REJECT_MGMT_FRAME   = 536,  /* add macaddress to reject mgmt pkts */
    IEEE80211_PARAM_DEL_MAC_REJECT_MGMT_FRAME   = 537,  /* del macaddress to reject mgmt pkts */
    IEEE80211_PARAM_ACTIVITY                    = 538,  /* Percentage of time the radio was unable to tx/rx pkts to/from clients */
    IEEE80211_PARAM_TXPOW                      = 539,   /* set/get the control frame tx power per vap */
    IEEE80211_PARAM_PRB_RATE                   = 540,   /* set/get probe-response frame rate */
    IEEE80211_PARAM_SOFTBLOCK_WAIT_TIME        = 541,   /* set/get wait time in softblcking */
    IEEE80211_PARAM_SOFTBLOCK_ALLOW_TIME       = 542,   /* set/get allow time in softblocking */
    IEEE80211_PARAM_OCE_HLP                    = 543,   /* Enable/disable OCE FILS HLP */
    IEEE80211_PARAM_NBR_SCAN_PERIOD            = 544,   /* set/get neighbor AP scan period */
    IEEE80211_PARAM_RNR                        = 545,   /* enable/disable inclusion of RNR IE in Beacon/Probe-Rsp */
    IEEE80211_PARAM_RNR_FD                     = 546,   /* enable/disable inclusion of RNR IE in FILS Discovery */
    IEEE80211_PARAM_RNR_TBTT                   = 547,   /* enable/disable calculation TBTT in RNR IE */
    IEEE80211_PARAM_AP_CHAN_RPT                = 548,   /* enable/disable inclusion of AP Channel Report IE in Beacon/Probe-Rsp */
    IEEE80211_PARAM_STEALTH_DOWN               = 549,   /* enable stealth mode interface down without explicitly disconnecting STAs */
    IEEE80211_PARAM_TIMEOUTIE                  = 550,   /* set/get assoc comeback timeout value */
    IEEE80211_PARAM_PMF_ASSOC                  = 551,   /* enable/disable pmf support */
    IEEE80211_PARAM_DFS_INFO_NOTIFY_APP        = 552,   /* Enable the feature to notify dfs info to app */
#ifdef TENDA_RSSI_LIMIT
    IEEE80211_PARAM_TD_RSSI_LIMIT               = 553,
#endif
    IEEE80211_PARAM_TD_WLAN_DEBUG               = 554,
    IEEE80211_PARAM_TD_WLAN_TUNNEL               = 555,
    IEEE80211_PARAM_SCAN_STATUS                = 556,
    IEEE80211_PARAM_TD_AP_MODE                  = 557,    
    IEEE80211_PARAM_TD_KICKMACALL               = 558,  /* add kickmacall by huangzhixin */
    IEEE80211_PARAM_TD_AUTO_HIDESSID            = 559,  /* enable/disable auto-hide ssid */
#ifdef ATH_TXHUNG_DEBUG
    IEEE80211_PARAM_TD_BUFF_INFO                = 560,  /* for ATH_TXHUNG_DEBUG */
#endif
#ifdef TENDA_TDMA /* Tenda:tdma add CLI,hongguiyang 201806 */
    IEEE80211_PARAM_TD_TDMA                     = 561,
#endif
#ifdef TENDA_SPEC_CHNL_WIDTH /* Tenda:spec chan width add CLI,hongguiyang 201806 */
    IEEE80211_PARAM_TD_SPEC_CHANNEL              = 562,
    IEEE80211_PARAM_TD_SPEC_WIDTH                = 563,
#endif
    IEEE80211_PARAM_TD_SM_CTRL                   = 564,
    IEEE80211_PARAM_TD_PROBE_BCAST_LMT           = 565,
    IEEE80211_PARAM_TD_ACS_SCAN                  = 566,
    IEEE80211_PARAM_TD_ACS_SCAN_RESULT           = 567,
#ifdef TD_TPC /* Tenda:tpc add CLI, hongguiyang 201806 */
    IEEE80211_PARAM_TD_TPC                       = 568,
#endif
};

#define IEEE80211_PARAM_DROPUNENCRYPTED     15 /* discard unencrypted frames */
#define IEEE80211_PARAM_WPA 10 /* WPA mode (0,1,2) */
#define WLAN_EID_RSN   48
#define IEEE80211_PARAM_CLR_APPOPT_IE     191
#define IEEE80211_IOC_WPS_MODE            632

#define IEEE80211_PARAM_UCASTCIPHER    8/* unicast cipher */
#define IEEE80211_PARAM_MCASTCIPHER    5/* multicast/default cipher */

#define IEEE80211_IOC_UCASTCIPHER     IEEE80211_PARAM_UCASTCIPHER    /* unicast cipher */
#define IEEE80211_IOC_MCASTCIPHER    IEEE80211_PARAM_MCASTCIPHER    /* multicast/default cipher */
#define IEEE80211_MLME_ASSOC 1

#define	IEEE80211_IOCTL_SETMLME		(SIOCIWFIRSTPRIV+6)
#define	IEEE80211_IOCTL_SETOPTIE	(SIOCIWFIRSTPRIV+8)
#define	IEEE80211_IOCTL_SETPARAM	(SIOCIWFIRSTPRIV+0)

#define IEEE80211_CIPHER_WEP           0
#define IEEE80211_CIPHER_TKIP          1
#define IEEE80211_CIPHER_AES_OCB       2
#define IEEE80211_CIPHER_AES_CCM       3
#define IEEE80211_CIPHER_WAPI          4
#define IEEE80211_CIPHER_CKIP          5
#define IEEE80211_CIPHER_AES_CMAC      6
#define IEEE80211_CIPHER_AES_CCM_256   7
#define IEEE80211_CIPHER_AES_CMAC_256  8
#define IEEE80211_CIPHER_AES_GCM       9
#define IEEE80211_CIPHER_AES_GCM_256   10
#define IEEE80211_CIPHER_AES_GMAC      11
#define IEEE80211_CIPHER_AES_GMAC_256  12
#define IEEE80211_CIPHER_NONE 13
#define IEEE80211_PARAM_AUTHMODE    3


typedef enum _ieee80211_auth_mode {
    IEEE80211_AUTH_NONE     = 0, /* deprecated */
    IEEE80211_AUTH_OPEN     = 1, /* open */
    IEEE80211_AUTH_SHARED   = 2, /* shared-key */
    IEEE80211_AUTH_8021X    = 3, /* 802.1x */
    IEEE80211_AUTH_AUTO     = 4, /* deprecated */
    IEEE80211_AUTH_WPA      = 5, /* WPA */
    IEEE80211_AUTH_RSNA     = 6, /* WPA2/RSNA */
    IEEE80211_AUTH_CCKM     = 7, /* CCK */
    IEEE80211_AUTH_WAPI     = 8, /* WAPI */
} ieee80211_auth_mode;


#endif
