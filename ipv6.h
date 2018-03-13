#ifndef _IPV6_H_
#define _IPV6_H_

#include <stdint.h>

typedef struct
{
    uint8_t b[16];
} IPv6Addr;

typedef struct
{
    uint8_t  _b0;
    uint8_t  _b1;
    uint8_t  _b2;
    uint8_t  _b3;
    uint16_t len;
    uint8_t  next_hdr;
    uint8_t  hop_limit;
    IPv6Addr src;
    IPv6Addr dst;
} IPv6Header;

#define ipv6_hdr_version(hdr)               (((hdr)->_b0 & 0xF0) >> 4)
#define ipv6_hdr_version_set(hdr, v)        do{ \
        (hdr)->_b0 = ((hdr)->_b0 & 0x0F) | (((v) & 0x0F) << 4); \
    }while(0)

#define ipv6_hdr_traffic_class(hdr)         ((((hdr)->_b0 & 0x0F) << 4) | (((hdr)->_b1 & 0xF0) >> 4))
#define ipv6_hdr_traffic_class_set(hdr, v)  do{ \
        (hdr)->_b0 = ((hdr)->_b0 & 0xF0) | (((v) & 0xF0) >> 4); \
        (hdr)->_b1 = ((hdr)->_b1 & 0x0F) | (((v) & 0x0F) << 4); \
    }while(0)

#define ipv6_hdr_flow_label(hdr)            (((uint32_t)((hdr)->_b1 & 0x0F) << 16) | ((uint32_t)(hdr)->_b2 << 8) | ((uint32_t)(hdr)->_b3))
#define ipv6_hdr_flow_label_set(hdr, v)     do{ \
        (hdr)->_b1 = ((hdr)->_b1 & 0xF0) | (((v) & 0xF0000) >> 16); \
        (hdr)->_b2 = ((v) & 0xFF00) >> 8; \
        (hdr)->_b3 = (v) & 0xFF; \
    }while(0)

typedef struct
{
    uint8_t  next_hdr;
    uint8_t  hdr_ext_len;
    uint16_t _s1;
} IPv6HeaderExtBase;

/***
 * "xxxx:xxxx:xxxx::xxxx:xxxx:xxxx" -> IPv6Addr
 * @param str NUL terminated string
 * @param addr Pointer to a IPv6Addr
 * @return 0 for success, -1 for failure
 */
int ipv6_aton(const char* str, IPv6Addr* addr);

/***
 * IPv6Addr -> "xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx"
 * @param addr Pointer to a IPv6Addr
 * @return A NUL terminated string within a static buffer
 */
const char* ipv6_ntoa(IPv6Addr* addr);

#endif /* _IPV6_H_ */
