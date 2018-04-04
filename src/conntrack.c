#include <string.h>
#include "tun2sock.h"
#include "conntrack.h"

//From lookup3.c
#define hashsize(n) ((uint32_t)1<<(n))
#define hashmask(n) (hashsize(n)-1)
uint32_t hashword(const uint32_t* k, size_t len, uint32_t initval);

int conntrack_init(ConnTrack* track, int ipver, void* (*realloc)(void*, size_t),
    int conn_max_size_bits, int conn_grow_step_bits,
    uint32_t (*time)(), uint32_t timeouts[CONN_ST_SIZE])
{
    if(track == NULL || (ipver != 4 && ipver != 6) || realloc == NULL || time == NULL || timeouts == NULL)
    {
        return TUN2SOCK_E_INVAL;
    }

    if(conn_max_size_bits <= 0 || conn_grow_step_bits <= 0 || conn_grow_step_bits > conn_max_size_bits)
    {
        return TUN2SOCK_E_INVAL;
    }

    track->ipver = ipver;

    track->realloc = realloc;

    track->pool = pool_create(realloc, (ipver == 4)? sizeof(Conn4) : sizeof(Conn6), 1 << conn_max_size_bits, 1 << conn_grow_step_bits);
    if(track->pool == NULL)
    {
        return TUN2SOCK_E_NOMEM;
    }

    track->ht_size_bits = (conn_max_size_bits > 3)? conn_max_size_bits - 3 : conn_max_size_bits;

    //Create hash initval using time()
    uint32_t now = time();
    track->ht_iv = hashword(&now, 1, 0);

    size_t ht_size = 1 << track->ht_size_bits;

    track->ht_conn = realloc(NULL, sizeof(PoolId) * ht_size * 2);
    if(track->ht_conn == NULL)
    {
        pool_delete(track->pool);
        return TUN2SOCK_E_NOMEM;
    }
    track->ht_nat = track->ht_conn + ht_size;

    size_t i;
    for(i = 0; i < ht_size; ++i)
    {
        track->ht_conn[i] = POOLID_NULL;
        track->ht_nat[i] = POOLID_NULL;
    }

    track->time = time;

    //The timeout list for free connections
    track->timeouts[0] = 0;
    track->timeout_lists[0].oldest = POOLID_NULL;
    track->timeout_lists[0].newest = POOLID_NULL;

    for(i = 1; i < CONN_ST_SIZE; ++i)
    {
        track->timeouts[i] = timeouts[i];
        track->timeout_lists[i].oldest = POOLID_NULL;
        track->timeout_lists[i].newest = POOLID_NULL;
    }

    track->last_nat_port = 0;

    return 0;
}

void conntrack_destroy(ConnTrack* track)
{
    track->realloc(track->ht_conn, 0);
    pool_delete(track->pool);
}

#define conn_timeout(c, t) ((c)->last_active + (t)->timeouts[(c)->state])

static uint32_t conntrack_nat_hash(int ipver, ConnTrack* track, uint8_t* addr, uint16_t port)
{
    struct
    {
        uint8_t addr[4];
        uint16_t port;
        uint16_t zero;
    } key4;

    struct
    {
        uint8_t addr[16];
        uint16_t port;
        uint16_t zero;
    } key6;

    void* key;
    size_t key_len;

    if(ipver == 4)
    {
        memcpy(key4.addr, addr, 4);
        key4.port = port;
        key4.zero = 0;

        key = &key4;
        key_len = sizeof(key4) / 4;
    }
    else
    {
        memcpy(key6.addr, addr, 16);
        key6.port = port;
        key6.zero = 0;

        key = &key6;
        key_len = sizeof(key6) / 4;
    }

    return hashword(key, key_len, track->ht_iv) & hashmask(track->ht_size_bits);
}

static uint32_t conntrack_nat_hash_conn(int ipver, ConnTrack* track, Conn* conn)
{
    if(ipver == 4)
    {
        Conn4* conn4 = (Conn4*)conn;
        return conntrack_nat_hash(4, track, conn4->ext_addr, conn4->nat_port);
    }
    else
    {
        Conn6* conn6 = (Conn6*)conn;
        return conntrack_nat_hash(6, track, conn6->ext_addr, conn6->nat_port);
    }
}

static void conntrack_remove_from_timeout(ConnTrack* track, PoolId id, Conn* conn)
{
    if(conn->timeout_next == id)
    {
        return;
    }

    if(conn->timeout_next == POOLID_NULL)
    {
        //Last in the list
        track->timeout_lists[conn->state].newest = conn->timeout_prev;
    }
    else
    {
        Conn* next = pool_ref(track->pool, conn->timeout_next);
        next->timeout_prev = conn->timeout_prev;
    }

    if(conn->timeout_prev == POOLID_NULL)
    {
        //First in the list
        track->timeout_lists[conn->state].oldest = conn->timeout_next;
    }
    else
    {
        Conn* prev = pool_ref(track->pool, conn->timeout_prev);
        prev->timeout_next = conn->timeout_next;
    }

    conn->timeout_prev = id;
    conn->timeout_next = id;

}

static void conntrack_add_to_timeout(ConnTrack* track, PoolId id, Conn* conn)
{
    if(track->timeout_lists[conn->state].newest != POOLID_NULL)
    {
        PoolId tail_id = track->timeout_lists[conn->state].newest;
        Conn* tail = pool_ref(track->pool, tail_id);
        tail->timeout_next = id;
        conn->timeout_prev = tail_id;
    }
    track->timeout_lists[conn->state].newest = id;

    if(track->timeout_lists[conn->state].oldest == POOLID_NULL)
    {
        track->timeout_lists[conn->state].oldest = id;
    }

    conn->timeout_next = POOLID_NULL;
}

static void conntrack_touch_now(ConnTrack* track, PoolId id, Conn* conn, ConnState state, uint32_t now)
{
    conntrack_remove_from_timeout(track, id, conn);
    conn->last_active = now;
    conn->state = state;
    conntrack_add_to_timeout(track, id, conn);
}

static void conntrack_add_to_conn(int ipver, ConnTrack* track, PoolId id, Conn* conn, uint32_t* hashp)
{
    uint32_t hash;
    if(hashp != NULL)
    {
        hash = *hashp;
    }
    else
    {
        hash = hashword((void*)conn + sizeof(Conn), (ipver == 4)? (4 + 2 + 4 + 2)/4 : (16 + 2 + 16 + 2)/4, track->ht_iv) & hashmask(track->ht_size_bits);
    }

    conn->ht_conn_prev = POOLID_NULL;
    conn->ht_conn_next = track->ht_conn[hash];
    track->ht_conn[hash] = id;
}


static void conntrack_remove_from_conn(int ipver, ConnTrack* track, PoolId id, Conn* conn, uint32_t* hashp)
{
    if(conn->ht_conn_next == id)
    {
        return;
    }

    if(conn->ht_conn_prev == POOLID_NULL)
    {
        uint32_t hash;
        if(hashp != NULL)
        {
            hash = *hashp;
        }
        else
        {
            hash = hashword((void*)conn + sizeof(Conn), (ipver == 4)? (4 + 2 + 4 + 2)/4 : (16 + 2 + 16 + 2)/4, track->ht_iv) & hashmask(track->ht_size_bits);
        }
        track->ht_conn[hash] = conn->ht_conn_next;
    }
    else
    {
        if(conn->ht_conn_next != POOLID_NULL)
        {
            Conn* next = pool_ref(track->pool, conn->ht_conn_next);
            next->ht_conn_prev = conn->ht_conn_prev;
        }
        Conn* prev = pool_ref(track->pool, conn->ht_conn_prev);
        prev->ht_conn_next = conn->ht_conn_next;
    }

    conn->ht_conn_next = id;
    conn->ht_conn_prev = id;
}

static void conntrack_add_to_nat(int ipver, ConnTrack* track, PoolId id, Conn* conn, uint32_t* hashp)
{
    uint32_t hash;
    if(hashp != NULL)
    {
        hash = *hashp;
    }
    else
    {
        if(ipver == 4)
        {
            Conn4* conn4 = (Conn4*)conn;
            hash = conntrack_nat_hash(ipver, track, conn4->ext_addr, conn4->nat_port);
        }
        else
        {
            Conn6* conn6 = (Conn6*)conn;
            hash = conntrack_nat_hash(ipver, track, conn6->ext_addr, conn6->nat_port);
        }
    }

    conn->ht_nat_prev = POOLID_NULL;
    conn->ht_nat_next = track->ht_nat[hash];
    track->ht_nat[hash] = id;
}

static void conntrack_remove_from_nat(int ipver, ConnTrack* track, PoolId id, Conn* conn, uint32_t* hashp)
{
    if(conn->ht_nat_next == id)
    {
        return;
    }

    if(conn->ht_nat_prev == POOLID_NULL)
    {
        uint32_t hash;
        if(hashp != NULL)
        {
            hash = *hashp;
        }
        else
        {
            hash = conntrack_nat_hash_conn(ipver, track, conn);
        }
        track->ht_nat[hash] = conn->ht_nat_next;
    }
    else
    {
        if(conn->ht_nat_next != POOLID_NULL)
        {
            Conn* next = pool_ref(track->pool, conn->ht_nat_next);
            next->ht_nat_prev = conn->ht_nat_prev;
        }
        Conn* prev = pool_ref(track->pool, conn->ht_nat_prev);
        prev->ht_nat_next = conn->ht_nat_next;
    }

    conn->ht_nat_prev = id;
    conn->ht_nat_next = id;
}

static int conntrack_nat_search(int ipver, ConnTrack* track, PoolId* id_out, Conn** conn_out, uint8_t* addr, uint16_t port, uint32_t* hash_out)
{
    uint32_t hash = conntrack_nat_hash(ipver, track, addr, port);
    if(hash_out != NULL)
    {
        *hash_out = hash;
    }

    uint32_t now = track->time();

    PoolId id = track->ht_nat[hash];
    while(id != POOLID_NULL)
    {
        Conn* conn = pool_ref(track->pool, id);

        //Cleanup timeout
        if(conn_timeout(conn, track) <= now)
        {
            id = conn->ht_nat_next;

            //Move timeout connection to free list
            conntrack_remove_from_conn(ipver, track, id, conn, NULL);
            conntrack_remove_from_nat(ipver, track, id, conn, &hash);
            conntrack_touch_now(track, id, conn, CONN_ST_FREE, now);

            continue;
        }

        int found = 0;
        if(ipver == 4)
        {
            Conn4* conn4 = (Conn4*)conn;
            if(conn4->nat_port == port && memcmp(conn4->ext_addr, addr, 4) == 0)
            {
                found = 1;
            }
        }
        else
        {
            Conn6* conn6 = (Conn6*)conn;
            if(conn6->nat_port == port && memcmp(conn6->ext_addr, addr, 16) == 0)
            {
                found = 1;
            }
        }

        if(found)
        {
            *id_out = id;
            *conn_out = conn;
            return 0;
        }

        id = conn->ht_nat_next;
    }

    return TUN2SOCK_E_NONAT;
}

/***
 * Create a new NAT and set nat_port and insert into NAT hash table
 * If failed, will not modify conn
 */
static int conntrack_new_nat(int ipver, ConnTrack* track, PoolId id, Conn* conn)
{
    uint16_t p = track->last_nat_port + 1;

    uint8_t* addr = (ipver == 4)? ((Conn4*)conn)->ext_addr : ((Conn6*)conn)->ext_addr;

    for(p = track->last_nat_port + 1; p != track->last_nat_port; ++p)
    {
        uint32_t hash;

        if(p == 0)
        {
            continue;
        }

        PoolId id_n = POOLID_NULL;
        Conn* conn_n = NULL;
        int ret = conntrack_nat_search(ipver, track, &id_n, &conn_n, addr, p, &hash);
        if(ret == 0)
        {
            continue;
        }
        else if(ret != TUN2SOCK_E_NONAT)
        {
            //Some error
            return ret;
        }


        //Usable port
        conntrack_add_to_nat(ipver, track, id, conn, &hash);

        if(ipver == 4)
        {
            Conn4* conn4 = (Conn4*)conn;
            conn4->nat_port = p;
        }
        else
        {
            Conn6* conn6 = (Conn6*)conn;
            conn6->nat_port = p;
        }

        track->last_nat_port = p;

        return 0;
    }

    return TUN2SOCK_E_MAXNAT;
}

static int conntrack_conn_search(int ipver, ConnTrack* track, PoolId* id_out, Conn** conn_out, uint8_t* saddr, uint16_t sport, uint8_t* daddr, uint16_t dport, int flags)
{
    if(track == NULL || conn_out == NULL || saddr == NULL || sport == 0 || daddr == NULL || dport == 0)
    {
        return TUN2SOCK_E_INVAL;
    }

    if(track->ipver != ipver)
    {
        return TUN2SOCK_E_INVAL;
    }

    struct
    {
        uint8_t saddr[4];
        uint16_t sport;
        uint8_t daddr[4];
        uint16_t dport;
    } key4;

    struct
    {
        uint8_t saddr[16];
        uint16_t sport;
        uint8_t daddr[16];
        uint16_t dport;
    } key6;

    void* key;
    size_t key_len;

    if(ipver == 4)
    {
        memcpy(key4.saddr, saddr, 4);
        key4.sport = sport;
        memcpy(key4.daddr, daddr, 4);
        key4.dport = dport;
        key = &key4;
        key_len = sizeof(key4) / 4;
    }
    else
    {
        memcpy(key6.saddr, saddr, 16);
        key6.sport = sport;
        memcpy(key6.daddr, daddr, 16);
        key6.dport = dport;
        key = &key6;
        key_len = sizeof(key6) / 4;
    }

    uint32_t hash = hashword(key, key_len, track->ht_iv) & hashmask(track->ht_size_bits);

    PoolId last_free = POOLID_NULL;
    Conn* last_free_conn = NULL;

    PoolId id = track->ht_conn[hash];
    uint32_t now = track->time();
    while(id != POOLID_NULL)
    {
        Conn* conn = pool_ref(track->pool, id);
        if(conn_timeout(conn, track) <= now)
        {
            //Timeout
            if(last_free == POOLID_NULL)
            {
                last_free = id;
                last_free_conn = conn;
            }
        }
        else
        {
            if(memcmp(key, (void*)conn + sizeof(Conn), key_len * 4) == 0)
            {
                //Found
                if((flags & CONNTRACK_CONN_SEARCH_FLAG_CREAT) && (flags & CONNTRACK_CONN_SEARCH_FLAG_EXCL))
                {
                    return TUN2SOCK_E_EXTCONN;
                }

                *id_out = id;
                *conn_out = conn;
                return 0;
            }
        }

        id = conn->ht_conn_next;
    }

    //Not found
    if(!(flags & CONNTRACK_CONN_SEARCH_FLAG_CREAT))
    {
        return TUN2SOCK_E_NOCONN;
    }

    if(last_free != POOLID_NULL)
    {
        conntrack_remove_from_conn(ipver, track, last_free, last_free_conn, &hash);
    }

    //Create new
    if(last_free == POOLID_NULL)
    {
        //First search all timeout lists
        int i;
        for(i = 0; i < CONN_ST_SIZE; ++i)
        {
            if(track->timeout_lists[i].oldest != POOLID_NULL)
            {
                PoolId id = track->timeout_lists[i].oldest;
                Conn* conn = pool_ref(track->pool, id);

                if(conn_timeout(conn, track) <= now)
                {
                    if(conn->ht_conn_next != id)
                    {
                        conntrack_remove_from_conn(ipver, track, id, conn, NULL);
                    }

                    last_free = id;
                    last_free_conn = conn;
                    break;
                }
            }
        }
    }

    if(last_free == POOLID_NULL)
    {
        //New one from pool
        int ret = pool_get(track->pool, &last_free, (void**)&last_free_conn);
        if(ret != 0)
        {
            switch(ret)
            {
                case -1:
                    return TUN2SOCK_E_MAXCONN;
                case -2:
                    return TUN2SOCK_E_NOMEM;
                default:
                    return TUN2SOCK_E_INTERNAL;
            }
        }

        last_free_conn->ht_conn_next = last_free;
        last_free_conn->ht_conn_prev = last_free;
        last_free_conn->ht_nat_next = last_free;
        last_free_conn->ht_nat_prev = last_free;
        last_free_conn->timeout_next = last_free;
        last_free_conn->timeout_prev = last_free;
    }

    conntrack_remove_from_nat(ipver, track, last_free, last_free_conn, NULL);

    conntrack_remove_from_timeout(track, last_free, last_free_conn);

    last_free_conn->last_active = 0;
    last_free_conn->state = CONN_ST_FREE;

    if(ipver == 4)
    {
        Conn4* conn4 = (Conn4*)last_free_conn;

        memcpy(conn4->int_addr, saddr, 4);
        conn4->int_port = sport;
        memcpy(conn4->ext_addr, daddr, 4);
        conn4->ext_port = dport;

        conn4->nat_port = 0;
    }
    else
    {
        Conn6* conn6 = (Conn6*)last_free_conn;

        memcpy(conn6->int_addr, saddr, 16);
        conn6->int_port = sport;
        memcpy(conn6->ext_addr, daddr, 16);
        conn6->ext_port = dport;

        conn6->nat_port = 0;
    }

    //As of now, last_free is a free connection not within any hash table or list

    int ret = conntrack_new_nat(ipver, track, last_free, last_free_conn);
    if(ret != 0)
    {
        //Failed to find a new NAT
        //Insert this free connection into the free list
        conntrack_touch(track, last_free, last_free_conn, CONN_ST_FREE);
        return ret;
    }

    conntrack_add_to_conn(ipver, track, last_free, last_free_conn, &hash);

    //Will not add newly created connection to timeout lists
    //The caller should call conntrack_touch() after this function returns which will add this to a timeout list

    *id_out = last_free;
    *conn_out = last_free_conn;
    return 0;
}

int conntrack_conn_search4(ConnTrack* track, PoolId* id, Conn4** conn, uint8_t saddr[4], uint16_t sport, uint8_t daddr[4], uint16_t dport, int flags)
{
    return conntrack_conn_search(4, track, id, (Conn**)conn, saddr, sport, daddr, dport, flags);
}

int conntrack_conn_search6(ConnTrack* track, PoolId* id, Conn6** conn, uint8_t saddr[16], uint16_t sport, uint8_t daddr[16], uint16_t dport, int flags)
{
    return conntrack_conn_search(6, track, id, (Conn**)conn, saddr, sport, daddr, dport, flags);
}

int conntrack_touch(ConnTrack* track, PoolId id, Conn* conn, ConnState state)
{
    conntrack_touch_now(track, id, conn, state, track->time());
    return 0;
}

int conntrack_nat_search4(ConnTrack* track, PoolId* id, Conn4** conn, uint8_t addr[4], uint16_t port)
{
    return conntrack_nat_search(4, track, id, (Conn**)conn, addr, port, NULL);
}

int conntrack_nat_search6(ConnTrack* track, PoolId* id, Conn6** conn, uint8_t addr[16], uint16_t port)
{
    return conntrack_nat_search(6, track, id, (Conn**)conn, addr, port, NULL);
}
