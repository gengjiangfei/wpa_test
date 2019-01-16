/*
 * OS specific functions
 * Copyright (c) 2005-2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef OS_H
#define OS_H

#define TEST_FAIL() 0

typedef long os_time_t;

struct os_time {
	os_time_t sec;
	os_time_t usec;
};

struct os_reltime {
	os_time_t sec;
	os_time_t usec;
};

struct os_tm {
	int sec; /* 0..59 or 60 for leap seconds */
	int min; /* 0..59 */
	int hour; /* 0..23 */
	int day; /* 1..31 */
	int month; /* 1..12 */
	int year; /* Four digit year */
};

#ifndef os_malloc
#define os_malloc(s) malloc((s))
#endif

#ifndef os_realloc
#define os_realloc(p, s) realloc((p), (s))
#endif

#ifndef os_free
#define os_free(p) free((p))
#endif

#ifndef os_strdup
#define os_strdup(s) strdup(s)
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

#ifndef os_strlen
#define os_strlen(s) strlen(s)
#endif
#ifndef os_strcasecmp

#define os_strcasecmp(s1, s2) strcasecmp((s1), (s2))
#endif
#ifndef os_strncasecmp
#define os_strncasecmp(s1, s2, n) strncasecmp((s1), (s2), (n))
#endif
#ifndef os_strchr
#define os_strchr(s, c) strchr((s), (c))
#endif
#ifndef os_strcmp
#define os_strcmp(s1, s2) strcmp((s1), (s2))
#endif
#ifndef os_strncmp
#define os_strncmp(s1, s2, n) strncmp((s1), (s2), (n))
#endif
#ifndef os_strrchr
#define os_strrchr(s, c) strrchr((s), (c))
#endif
#ifndef os_strstr
#define os_strstr(h, n) strstr((h), (n))
#endif

#ifndef os_snprintf
#define os_snprintf snprintf
#endif

static inline int os_snprintf_error(size_t size, int res)
{
	return res < 0 || (unsigned int) res >= size;
}

static inline void * os_realloc_array(void *ptr, size_t nmemb, size_t size)
{
	if (size && nmemb > (~(size_t) 0) / size)
		return NULL;
	return os_realloc(ptr, nmemb * size);
}

/**
 * os_remove_in_array - Remove a member from an array by index
 * @ptr: Pointer to the array
 * @nmemb: Current member count of the array
 * @size: The size per member of the array
 * @idx: Index of the member to be removed
 */
static inline void os_remove_in_array(void *ptr, size_t nmemb, size_t size,
				      size_t idx)
{
	if (idx < nmemb - 1)
		os_memmove(((unsigned char *) ptr) + idx * size,
			   ((unsigned char *) ptr) + (idx + 1) * size,
			   (nmemb - idx - 1) * size);
}

/**
 * os_strlcpy - Copy a string with size bound and NUL-termination
 * @dest: Destination
 * @src: Source
 * @siz: Size of the target buffer
 * Returns: Total length of the target string (length of src) (not including
 * NUL-termination)
 *
 * This function matches in behavior with the strlcpy(3) function in OpenBSD.
 */
size_t os_strlcpy(char *dest, const char *src, size_t siz);

/**
 * os_memcmp_const - Constant time memory comparison
 * @a: First buffer to compare
 * @b: Second buffer to compare
 * @len: Number of octets to compare
 * Returns: 0 if buffers are equal, non-zero if not
 *
 * This function is meant for comparing passwords or hash values where
 * difference in execution time could provide external observer information
 * about the location of the difference in the memory buffers. The return value
 * does not behave like os_memcmp(), i.e., os_memcmp_const() cannot be used to
 * sort items into a defined order. Unlike os_memcmp(), execution time of
 * os_memcmp_const() does not depend on the contents of the compared memory
 * buffers, but only on the total compared length.
 */
int os_memcmp_const(const void *a, const void *b, size_t len);

/**
 * os_exec - Execute an external program
 * @program: Path to the program
 * @arg: Command line argument string
 * @wait_completion: Whether to wait until the program execution completes
 * Returns: 0 on success, -1 on error
 */
int os_exec(const char *program, const char *arg, int wait_completion);
void * os_zalloc(size_t size);
char * os_readfile(const char *name, size_t *len);

#endif /* OS_H */
