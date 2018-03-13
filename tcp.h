#ifndef _TCP_H_
#define _TCP_H_

#include <stdint.h>

#define PROTOCOL_TCP 6

typedef struct
{
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t  _b12;
    uint8_t  _b13;
    uint16_t win;
    uint16_t checksum;
    uint16_t urgent_ptr;
} TCPHeader;

#define tcp_hdr_dataoff(hdr)            (((hdr)->_b12 & 0xF0) >> 4)
#define tcp_hdr_dataoff_set(hdr, v)     do{ \
        (hdr)->_b12 = ((hdr)->_b12 & 0x0F) | (((v) & 0x0F) << 4); \
    }while(0)

#define tcp_hdr_flags_NS                0x0100
#define tcp_hdr_flags_CWR               0x0080
#define tcp_hdr_flags_ECE               0x0040
#define tcp_hdr_flags_URG               0x0020
#define tcp_hdr_flags_ACK               0x0010
#define tcp_hdr_flags_PSH               0x0008
#define tcp_hdr_flags_RST               0x0004
#define tcp_hdr_flags_SYN               0x0002
#define tcp_hdr_flags_FIN               0x0001
#define tcp_hdr_flags(hdr)              ((((hdr)->_b12 & 0x01) << 8) | ((hdr)->_b13))
#define tcp_hdr_flgas_set(hdr, v)       do{ \
        (hdr)->_b12 = ((hdr)->_b12 & 0x01) | (((v) & 0x0100) >> 8); \
        (hdr)->_b13 = (v) & 0xFF; \
    }while(0)

#endif /* _TCP_H_ */
