#include <inttypes.h>
#include <limits.h>

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