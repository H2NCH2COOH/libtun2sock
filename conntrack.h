#ifndef _CONNTRACK_H_
#define _CONNTRACK_H_

#include <stdint.h>
#include "pool.h"

typedef struct
{
    uint8_t  int_addr[4];
    uint16_t int_port;

    uint8_t  ext_addr[4];
    uint16_t ext_port;

    uint16_t nat_port;

    uint32_t last_active;

    PoolId conn_ht_next;
    PoolId nat_ht_next;

    PoolId timeout_next;
    PoolId timeout_prev;
} Conn4;

typedef struct
{
    uint8_t  int_addr[16];
    uint16_t int_port;

    uint8_t  ext_addr[16];
    uint16_t ext_port;

    uint16_t nat_port;

    uint32_t last_active;

    PoolId conn_ht_next;
    PoolId nat_ht_next;

    PoolId timeout_next;
    PoolId timeout_prev;
} Conn6;

typedef struct
{
    int ipver;

    Pool* pool;

    int ht_size_bits;

    PoolId* ht_conn;
    PoolId* ht_nat;

    int timeout_lists_cnt;
    struct
    {
        PoolId oldest;
        PoolId newest;
    }* timeout_lists;
} ConnTrack;

/***
 * Init a connection track
 * @param track                 The connection track to init
 * @param ipver                 The version of IP (4 or 6)
 * @param realloc               The realloc function
 * @param conn_max_size_bits    The number of bits of the maximum count of connections
 *                              A value of N means that only (2 ** N) number of connection can be tracked
 *                              TODO: Support to grow indefinitely
 * @param conn_grow_step_bits   The number of bits of the number of new connection to allocate from memory
 *                              A value of M means that each time new connection need to be allocated from memory, (2 ** M) connections is allocted
 *                              Must be smaller than or equal to conn_max_size_bits
 * @return                      0  Success
 *                              <0 Error number
 */
int conntrack_init(ConnTrack* track, int ipver, void* (*realloc)(void*, size_t), int conn_max_size_bits, int conn_grow_step_bits);

/***
 * Search for a connection using source & destination address
 * And get a optional new connection
 * @param track         The connection track
 * @param conn          The found connection output pointer
 * @param saddr         The source IP address
 * @param sport         The source port
 * @param daddr         The destination IP address
 * @param dport         The destination port
 * @param flags         Flags CONNTRACK_CONN_SEARCH_FLAGS_* ORed
 * @return              0  Success
 *                      <0 Error number
 */
int conntrack_conn_search4(ConnTrack* track, Conn4** conn, uint8_t saddr[4], uint16_t sport, uint8_t daddr[4], uint16_t dport, int flags);
int conntrack_conn_search6(ConnTrack* track, Conn6** conn, uint8_t saddr[16], uint16_t sport, uint8_t daddr[16], uint16_t dport, int flags);
#define CONNTRACK_CONN_SEARCH_FLAG_CREATE      1

#endif /* _CONNTRACK_H_ */
