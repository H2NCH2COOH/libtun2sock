#ifndef _CONNTRACK_H_
#define _CONNTRACK_H_

#include <stdint.h>
#include "pool.h"

typedef enum
{
    CONN_ST_FREE = 0,
    CONN_ST_DFT,
    //TODO: Add TCP states

    CONN_ST_SIZE
} ConnState;

typedef struct
{
    ConnState state;

    uint32_t last_active;

    PoolId ht_conn_next;
    PoolId ht_conn_prev;

    PoolId ht_nat_next;
    PoolId ht_nat_prev;

    PoolId timeout_next;
    PoolId timeout_prev;
} Conn;


typedef struct
{
    Conn conn;

    uint8_t  int_addr[4];
    uint16_t int_port;

    uint8_t  ext_addr[4];
    uint16_t ext_port;

    uint16_t nat_port;
} Conn4;

typedef struct
{
    Conn conn;

    uint8_t  int_addr[16];
    uint16_t int_port;

    uint8_t  ext_addr[16];
    uint16_t ext_port;

    uint16_t nat_port;
} Conn6;

typedef struct
{
    int ipver;

    void* (*realloc)(void*, size_t);
    Pool* pool;

    int ht_size_bits;
    uint32_t ht_iv;
    PoolId* ht_conn;
    PoolId* ht_nat;

    uint32_t (*time)();

    uint32_t timeouts[CONN_ST_SIZE];
    struct
    {
        PoolId oldest;
        PoolId newest;
    } timeout_lists[CONN_ST_SIZE];

    uint16_t last_nat_port;
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
 * @param time                  The time function
 * @param timeouts              An array of timeouts
 *                              Each value in this array correspond to the timeout for connection in that state (See ConnState)
 *                              The first entry of this array is ignored (The state CONN_ST_FREE is used internally)
 * @param
 * @return                      0  Success
 *                              <0 Error number
 */
int conntrack_init(ConnTrack* track, int ipver, void* (*realloc)(void*, size_t),
    int conn_max_size_bits, int conn_grow_step_bits,
    uint32_t (*time)(), uint32_t timeouts[CONN_ST_SIZE]);

/***
 * Destroy and a connection track
 * @param track                 The connection track to destroy
 */
void conntrack_destroy(ConnTrack* track);

/***
 * Search for a connection using source & destination address
 * And get a optional new connection
 * The newly created connection is already touched (No need to call conntrack_touch())
 * @param track         The connection track
 * @param id            The id of the found connection
 * @param conn          The found connection
 * @param saddr         The source IP address
 * @param sport         The source port
 * @param daddr         The destination IP address
 * @param dport         The destination port
 * @param flags         Flags CONNTRACK_CONN_SEARCH_FLAGS_* ORed
 * @return              0  Success
 *                      <0 Error number
 */
#define CONNTRACK_CONN_SEARCH_FLAG_CREAT       1 //Create a new connection if no existing one is found
#define CONNTRACK_CONN_SEARCH_FLAG_EXCL        2 //Must be used with CREAT, fail when existing one is found
int conntrack_conn_search4(ConnTrack* track, PoolId* id, Conn4** conn, uint8_t saddr[4], uint16_t sport, uint8_t daddr[4], uint16_t dport, int flags);
int conntrack_conn_search6(ConnTrack* track, PoolId* id, Conn6** conn, uint8_t saddr[16], uint16_t sport, uint8_t daddr[16], uint16_t dport, int flags);

/***
 * This function should be called when a connection received traffic (and change state)
 * @param track         The connection track
 * @param id            The id of the connection
 * @param conn          The connection
 * @param state         The new connection state (Cannot be CONN_ST_FREE)
 * @return              0  Success
 *                      <0 Error number
 */
int conntrack_touch(ConnTrack* track, PoolId id, Conn* conn, ConnState state);

/***
 * Search for a connection using NAT address
 * @param track         The connection track
 * @param id            The id of the found connection
 * @param conn          The found connection
 * @param addr          The IP address
 * @param port          The NAT port
 * @return              0  Success
 *                      <0 Error number
 */
int conntrack_nat_search4(ConnTrack* track, PoolId* id, Conn4** conn, uint8_t addr[4], uint16_t port);
int conntrack_nat_search6(ConnTrack* track, PoolId* id, Conn6** conn, uint8_t addr[16], uint16_t port);

#endif /* _CONNTRACK_H_ */
