#include <inttypes.h>
#include <limits.h>

#ifdef __BPF__
#define SEC(NAME) __attribute__((section(NAME), used))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) ((__be16)___constant_swab16((x)))
#define ntohs(x) ((__be16)___constant_swab16((x)))
#define htonl(x) ((__be32)___constant_swab32((x)))
#define ntohl(x) ((__be32)___constant_swab32((x)))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htons(x) (x)
#define ntohs(X) (x)
#define htonl(x) (x)
#define ntohl(x) (x)
#endif

#ifndef printk
# define printk(fmt, ...)                                      \
    ({                                                         \
        char ____fmt[] = fmt;                                  \
        trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
#endif

#ifndef offsetof
# define offsetof(TYPE, MEMBER)	((uint16_t)&((TYPE *)0)->MEMBER)
#endif
#endif

#define BASEDIR_MAPS "/sys/fs/bpf/tc/globals"

__always_inline uint64_t mac2int(const uint8_t hwaddr[])
{
    int8_t i;
    uint64_t ret = 0;
    const uint8_t *p = hwaddr;

    for (i = 5; i >= 0; i--) 
    {
        ret |= (uint64_t) *p++ << (CHAR_BIT * i);
    }

    return ret;
}

__always_inline void int2mac(const uint64_t mac, uint8_t *hwaddr)
{
    int8_t i;
    uint8_t *p = hwaddr;

    for (i = 5; i >= 0; i--) 
    {
        *p++ = mac >> (CHAR_BIT * i);
    }
}