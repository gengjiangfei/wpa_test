#ifndef MAIN_H
#define MAIN_H

#include "common.h"

#define _BYTE_ORDER _BIG_ENDIAN
#include "ieee80211_external.h"
#undef WPA_OUI_TYPE
#undef MBO_OUI_TYPE

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

#endif


