#ifndef _CONNTRACK_H_
#define _CONNTRACK_H_

#include <stdint.h>

typedef struct Conn4_s
{
    uint8_t  int_addr[4];
    uint16_t int_port;

    uint8_t  ext_addr[4];
    uint16_t ext_port;

    uint16_t nat_port;

    uint32_t last_active;

    struct Conn4_s* conn_ht_next;
    struct Conn4_s* nat_ht_next;

    struct Conn4_s* next;
    struct Conn4_s* prev;
} Conn4;

typedef struct Conn6_s
{
    uint8_t  int_addr[16];
    uint16_t int_port;

    uint8_t  ext_addr[16];
    uint16_t ext_port;

    uint16_t nat_port;

    uint32_t last_active;

    struct Conn6_s* conn_ht_next;
    struct Conn6_s* nat_ht_next;

    struct Conn6_s* next;
    struct Conn6_s* prev;
} Conn6;

#endif /* _CONNTRACK_H_ */
