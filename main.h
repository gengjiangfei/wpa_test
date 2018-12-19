#ifndef MAIN_H
#define MAIN_H

#ifndef MACSTR
#define MACSTR      "%02x:%02x:%02x:%02x:%02x:%02x"
#endif

#ifndef MAC2STR
#define MAC2STR(a)  (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#endif

#define CONFIG_CRYPTO_INTERNAL
//enum {
//	MSG_EXCESSIVE, MSG_MSGDUMP, MSG_DEBUG, MSG_INFO, MSG_WARNING, MSG_ERROR
//};
struct dl_list {
	struct dl_list *next;
	struct dl_list *prev;
};

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


