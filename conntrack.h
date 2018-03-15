#ifndef _CONNTRACK_H_
#define _CONNTRACK_H_

#include <stdint.h>

typedef struct
{
    uint8_t  int_addr[4];
    uint16_t int_port;

    uint8_t  ext_addr[4];
    uint16_t nat_ext_port;
    uint16_t ori_ext_port;

    uint32_t last_active;
} Conn4;

typedef struct
{
    uint8_t  int_addr[16];
    uint16_t int_port;

    uint8_t  ext_addr[16];
    uint16_t nat_ext_port;
    uint16_t ori_ext_port;

    uint32_t last_active;
} Conn6;


#endif /* _CONNTRACK_H_ */
