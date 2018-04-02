#include <string.h>
#include "tun2sock.h"
#include "conntrack.h"
#include "protocol.h"
#include "ipv4.h"
#include "ipv6.h"
#include "tcp.h"
#include "udp.h"

typedef struct
{
    ConnTrack* track4;
    ConnTrack* track6;
} Tun2SockCtx;

int tun2sock_init(Tun2Sock* t2s)
{
    int err = TUN2SOCK_E_INTERNAL;

    uint8_t zeros[16];
    uint8_t ones[16];

    memset(zeros, 0, sizeof(zeros));
    memset(ones, 0xFF, sizeof(ones));

    if(t2s == NULL)
    {
        return TUN2SOCK_E_INVAL;
    }

    if(
        t2s->realloc == NULL ||
        t2s->time == NULL ||
        (t2s->flags & (TUN2SOCK_FLAG_IPV4 | TUN2SOCK_FLAG_IPV6)) == 0 ||
        t2s->timeout == 0 ||
        t2s->max_connections_bits <= 0
    )
    {
        return TUN2SOCK_E_INVAL;
    }

    size_t ctx_size = sizeof(Tun2SockCtx);

    if(t2s->flags & TUN2SOCK_FLAG_IPV4)
    {
        if(t2s->target_port4 == 0)
        {
            return TUN2SOCK_E_INVAL;
        }

        if(memcmp(t2s->target_addr4, zeros, 4) == 0 || memcmp(t2s->target_addr4, ones, 4) == 0)
        {
            return TUN2SOCK_E_INVAL;
        }

        ctx_size += sizeof(ConnTrack);
    }

    if(t2s->flags & TUN2SOCK_FLAG_IPV6)
    {
        if(t2s->target_port6 == 0)
        {
            return TUN2SOCK_E_INVAL;
        }

        if(memcmp(t2s->target_addr6, zeros, 16) == 0 || memcmp(t2s->target_addr6, ones, 16) == 0)
        {
            return TUN2SOCK_E_INVAL;
        }

        ctx_size += sizeof(ConnTrack);
    }

    Tun2SockCtx* ctx = t2s->realloc(NULL, ctx_size);
    if(ctx == NULL)
    {
        return TUN2SOCK_E_NOMEM;
    }

    ctx->track4 = NULL;
    ctx->track6 = NULL;

    uint32_t timeouts[CONN_ST_SIZE];
    timeouts[CONN_ST_DFT] = t2s->timeout;

    if(t2s->flags & TUN2SOCK_FLAG_IPV4)
    {
        ConnTrack* track4 = (void*)ctx + sizeof(Tun2SockCtx);

        err = conntrack_init(track4, 4, t2s->realloc, t2s->max_connections_bits, t2s->max_connections_bits, t2s->time, timeouts);
        if(err != 0)
        {
            goto error;
        }

        ctx->track4 = track4;
    }

    if(t2s->flags & TUN2SOCK_FLAG_IPV6)
    {
        ConnTrack* track6 = (void*)ctx + sizeof(Tun2SockCtx);

        err = conntrack_init(track6, 6, t2s->realloc, t2s->max_connections_bits, t2s->max_connections_bits, t2s->time, timeouts);
        if(err != 0)
        {
            goto error;
        }

        ctx->track6 = track6;
    }

    return 0;

error:
    if(ctx != NULL)
    {
        if(ctx->track4 != NULL)
        {
            conntrack_destroy(ctx->track4);
        }

        if(ctx->track6 != NULL)
        {
            conntrack_destroy(ctx->track6);
        }

        t2s->realloc(ctx, 0);
    }

    return err;
}


