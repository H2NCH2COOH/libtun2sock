#ifndef _IPV4_H_
#define _IPV4_H_

#include <stdint.h>

typedef struct
{
    uint8_t b[4];
} IPv4Addr;

typedef struct
{
    uint8_t  _b0;
    uint8_t  _b1;
    uint8_t  len[2];
    uint16_t id;
    uint8_t  _b6;
    uint8_t  _b7;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    IPv4Addr src;
    IPv4Addr dst;
} IPv4Header;

#define ipv4_hdr_version(hdr)           (((hdr)->_b0 & 0xF0) >> 4)
#define ipv4_hdr_version_set(hdr, v)    do{ \
        (hdr)->_b0 = ((hdr)->_b0 & 0x0F) | (((v) & 0x0F) << 4); \
    }while(0)

#define ipv4_hdr_ihl(hdr)               ((hdr)->_b0 & 0x0F)
#define ipv4_hdr_ihl_set(hdr, v)        do{ \
        (hdr)->_b0 = ((hdr)->_b0 & 0xF0) | ((v) & 0x0F); \
    }while(0)

#define ipv4_hdr_dscp(hdr)              (((hdr)->_b1 & 0xFC) >> 2)
#define ipv4_hdr_dscp_set(hdr, v)       do{ \
        (hdr)->_b1 = ((hdr)->_b1 & 0x03) | (((v) & 0x3F) << 2); \
    }while(0)

#define ipv4_hdr_ecn(hdr)               ((hdr)->_b1 & 0x03)
#define ipv4_hdr_ecn_set(hdr, v)        do{ \
        (hdr)->_b1 = ((hdr)->_b1 & 0xFC) | ((v) & 0x03); \
    }while(0)

#define ipv4_hdr_len(hdr)               (((hdr)->len[0] << 8) | (hdr)->len[1])
#define ipv4_hdr_len_set(hdr, l)        do{ \
        (hdr)->len[0] = ((l) & 0xFF00) >> 8; \
        (hdr)->len[1] = (l) & 0xFF; \
    }while(0)

#define ipv4_hdr_flags_DF               0x40
#define ipv4_hdr_flags_MF               0x20
#define ipv4_hdr_flags(hdr)             ((hdr)->_b6 & 0xE0)
#define ipv4_hdr_flags_set(hdr, v)      do{ \
        (hdr)->_b6 = ((hdr)->_b6 & 0x1F) | ((v) & 0xE0); \
    }while(0)

#define ipv4_hdr_frag_offset(hdr)       ((((hdr)->_b6 & 0x1F) << 8) | (hdr)->_b7)
#define ipv4_hdr_frag_offset_set(hdr, v)        do{ \
        (hdr)->_b6 = ((hdr)->_b6 & 0xE0) | (((v) & 0x1F00) >> 8); \
        (hdr)->_b7 = (v) & 0xFF; \
    }while(0)

/***
 * "xxx.xxx.xxx.xxx" -> IPv4Addr
 * @param str NUL terminated string
 * @param addr Pointer to a IPv4Addr
 * @return 0 for success, -1 for failure
 */
int ipv4_aton(const char* str, IPv4Addr* addr);

/***
 * IPv4Addr -> "xxx.xxx.xxx.xxx"
 * @param addr Pointer to a IPv4Addr
 * @return A NUL terminated string within a static buffer
 */
const char* ipv4_ntoa(IPv4Addr* addr);

/***
 * Calculate and set the checksum of IPv4 header
 * @param hdr Pointer to a IPv4Header
 */
void ipv4_hdr_calc_checksum(IPv4Header* hdr);

/***
 * Check the checksum of IPv4 header
 * @param hdr Pointer to a IPv4Header
 * @return 0 for success, -1 for failure
 */
int ipv4_hdr_check_checksum(IPv4Header* hdr);

#endif /* _IPV4_H_ */
