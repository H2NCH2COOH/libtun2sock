#include <config.h>
#include <string.h>
#include "tun2sock.h"
#include "conntrack.h"
#include "protocol.h"
#include "ipv4.h"
#include "ipv6.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"

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
        ConnTrack* track4 = (ConnTrack*)(ctx + 1);

        err = conntrack_init(track4, 4, t2s->realloc, t2s->max_connections_bits, t2s->max_connections_bits, t2s->time, timeouts);
        if(err != 0)
        {
            goto error;
        }

        ctx->track4 = track4;
    }

    if(t2s->flags & TUN2SOCK_FLAG_IPV6)
    {
        ConnTrack* track6 = (ctx->track4 != NULL)? ctx->track4 + 1 : (ConnTrack*)(ctx + 1);

        err = conntrack_init(track6, 6, t2s->realloc, t2s->max_connections_bits, t2s->max_connections_bits, t2s->time, timeouts);
        if(err != 0)
        {
            goto error;
        }

        ctx->track6 = track6;
    }

    t2s->internal = ctx;

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

void tun2sock_cleanup(Tun2Sock* t2s)
{
    Tun2SockCtx* ctx = t2s->internal;

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

const char* tun2sock_strerr(int err)
{
    switch(err)
    {
        case TUN2SOCK_E_SUCCESS:
            return "Success";
        case TUN2SOCK_E_INVAL:
            return "Invalid value(s)";
        case TUN2SOCK_E_NOMEM:
            return "Not enough memory";
        case TUN2SOCK_E_INTERNAL:
            return "Internal error";
        case TUN2SOCK_E_DRPPKT:
            return "Packet should be dropped";
        case TUN2SOCK_E_BADPKT:
            return "Bad packet";
        case TUN2SOCK_E_PROTO:
            return "Unsupported protocol";
        case TUN2SOCK_E_NOCONN:
            return "Connection entry not found";
        case TUN2SOCK_E_NONAT:
            return "NAT entry not found";
        case TUN2SOCK_E_MAXCONN:
            return "Too many connections";
        case TUN2SOCK_E_MAXNAT:
            return "Too many connections to one IP address";
        case TUN2SOCK_E_EXTCONN:
            return "Connection already exists";
        default:
            return "Unknown error";
    }
}

void tun2sock_get_version(int* major, int* minor)
{
    if(major != NULL)
    {
        *major = PACKAGE_VERSION_MAJOR;
    }

    if(minor != NULL)
    {
        *minor = PACKAGE_VERSION_MINOR;
    }
}

static int tun2sock_error_resp(Tun2Sock* t2s, int err, int ipver, uint8_t* l3hdr, int l4proto, uint8_t* l4hdr)
{
    switch(err)
    {
        case TUN2SOCK_E_DRPPKT:
        case TUN2SOCK_E_MAXCONN:
        case TUN2SOCK_E_MAXNAT:
            //Try to generate error response
            break;
        default:
            return err;
    }

    IPv4Header ipv4hdr_out;
    IPv6Header ipv6hdr_out;

    size_t pkt_len = 0;
    uint8_t* saddr;
    uint8_t* daddr;
    uint8_t* proto;

    if(ipver == 4)
    {
        IPv4Header* ipv4hdr = (IPv4Header*)l3hdr;

        ipv4_hdr_version_set(&ipv4hdr_out, 4);
        ipv4_hdr_ihl_set(&ipv4hdr_out, 5);
        ipv4_hdr_dscp_set(&ipv4hdr_out, 0);
        ipv4_hdr_ecn_set(&ipv4hdr_out, 0);

        //Set length later

        //XXX: I don't really know how to handle this field
        ipv4hdr_out.id = ipv4hdr->id;

        ipv4_hdr_flags_set(&ipv4hdr_out, 0);
        ipv4_hdr_frag_offset_set(&ipv4hdr_out, 0);

        ipv4hdr_out.ttl = 64;

        //protocol will be set later
        proto = &ipv4hdr_out.protocol;

        //Calc checksum later

        memcpy(ipv4hdr_out.src.b, ipv4hdr->dst.b, 4);
        memcpy(ipv4hdr_out.dst.b, ipv4hdr->src.b, 4);

        pkt_len += sizeof(IPv4Header);

        saddr = ipv4hdr_out.src.b;
        daddr = ipv4hdr_out.dst.b;
    }
    else
    {
        IPv6Header* ipv6hdr = (IPv6Header*)l3hdr;

        ipv6_hdr_version_set(&ipv6hdr_out, 6);
        ipv6_hdr_traffic_class_set(&ipv6hdr_out, 0);
        ipv6_hdr_flow_label_set(&ipv6hdr_out, 0);

        //Set length later

        //protocol will be set later
        proto = &ipv6hdr_out.next_hdr;

        ipv6hdr_out.hop_limit = 64;

        memcpy(ipv6hdr_out.src.b, ipv6hdr->dst.b, 16);
        memcpy(ipv6hdr_out.dst.b, ipv6hdr->src.b, 16);

        pkt_len += sizeof(IPv6Header);

        saddr = ipv6hdr_out.src.b;
        daddr = ipv6hdr_out.dst.b;
    }

    if(l4proto == PROTO_TCP && !(t2s->flags & TUN2SOCK_FLAG_NO_TCP_RST_ERR_RSP))
    {
        TCPHeader* tcphdr = (TCPHeader*)l4hdr;
        TCPHeader tcphdr_out;
        memset(&tcphdr_out, 0, sizeof(TCPHeader));

        tcphdr_out.sport = tcphdr->dport;
        tcphdr_out.dport = tcphdr->sport;

        //XXX: This should work
        tcphdr_out.seq = 0;

        uint32_t ack = tcphdr->seq;
        uint8_t* ackb = (uint8_t*)&ack;

        ++ackb[3];
        if(ackb[3] == 0) ++ackb[2];
        if(ackb[2] == 0) ++ackb[1];
        if(ackb[1] == 0) ++ackb[0];

        tcphdr_out.ack = ack;

        tcp_hdr_dataoff_set(&tcphdr_out, 5);

        tcp_hdr_flgas_set(&tcphdr_out, tcp_hdr_flags_RST | tcp_hdr_flags_ACK);

        tcphdr_out.win = 0;

        tcphdr_out.urgent_ptr = 0;

        pkt_len += sizeof(TCPHeader);

        //Fill protocol field in IP header
        *proto = PROTO_TCP;

        uint8_t* ptr = l3hdr;
        if(ipver == 4)
        {
            ipv4_hdr_len_set(&ipv4hdr_out, pkt_len);
            ipv4_hdr_calc_checksum(&ipv4hdr_out);
            memcpy(ptr, &ipv4hdr_out, sizeof(IPv4Header));
            ptr += sizeof(IPv4Header);

            tcp4_hdr_calc_checksum(saddr, daddr, &tcphdr_out, 0);
        }
        else
        {
            ipv6_hdr_len_set(&ipv6hdr_out, pkt_len);
            memcpy(ptr, &ipv6hdr_out, sizeof(IPv6Header));
            ptr += sizeof(IPv6Header);

            tcp6_hdr_calc_checksum(saddr, daddr, &tcphdr_out, 0);
        }

        memcpy(ptr, &tcphdr_out, sizeof(TCPHeader));

        return (int)pkt_len;
    }
    else if(t2s->flags & TUN2SOCK_FLAG_NO_ICMP_ERR_RSP)
    {
        return err;
    }
    else
    {
        //Generate ICMP destination unreachable
        uint8_t* ptr = l3hdr;
        size_t data_len = l4hdr - l3hdr + 8;
        memmove(ptr + pkt_len + sizeof(ICMPHeader), l3hdr, data_len); //pkt_len should be the IP header length
        pkt_len += data_len;

        ICMPHeader icmphdr_out;
        if(ipver == 4)
        {
            icmphdr_out.type = 3;
            icmphdr_out.code = 0;
            icmphdr_out.zero = 0;

            pkt_len += sizeof(ICMPHeader);

            *proto = PROTO_ICMP;
            ipv4_hdr_len_set(&ipv4hdr_out, pkt_len);
            ipv4_hdr_calc_checksum(&ipv4hdr_out);
            memcpy(ptr, &ipv4hdr_out, sizeof(IPv4Header));
            ptr += sizeof(IPv4Header);

            memcpy(ptr, &icmphdr_out, sizeof(ICMPHeader));
            icmp4_hdr_calc_checksum((ICMPHeader*)ptr, data_len);
        }
        else
        {
            icmphdr_out.type = 1;
            icmphdr_out.code = 0;
            icmphdr_out.zero = 0;

            pkt_len += sizeof(ICMPHeader);

            *proto = PROTO_IPv6_ICMP;
            ipv6_hdr_len_set(&ipv6hdr_out, pkt_len);
            memcpy(ptr, &ipv6hdr_out, sizeof(IPv6Header));
            ptr += sizeof(IPv6Header);

            memcpy(ptr, &icmphdr_out, sizeof(ICMPHeader));
            icmp6_hdr_calc_checksum(saddr, daddr, (ICMPHeader*)ptr, data_len);
        }

        return (int)pkt_len;
    }
}

int tun2sock_input(Tun2Sock* t2s, uint8_t* pkt)
{
    if(t2s == NULL || t2s->internal == NULL || pkt == NULL)
    {
        return TUN2SOCK_E_INVAL;
    }

    Tun2SockCtx* ctx = t2s->internal;

    IPv4Header* ipv4hdr = (IPv4Header*)pkt;
    IPv6Header* ipv6hdr = (IPv6Header*)pkt;
    uint8_t* saddr;
    uint8_t* daddr;

    int ipver = ipv4_hdr_version(ipv4hdr);

    if(ipver != 4 && ipver != 6)
    {
        return TUN2SOCK_E_PROTO;
    }

    size_t pkt_len = (ipver == 4)? ipv4_hdr_len(ipv4hdr) : ipv6_hdr_len(ipv6hdr);

    uint8_t* l4hdr;
    size_t l4_len;
    int protocol;

    if(ipver == 4)
    {
        if(!(t2s->flags & TUN2SOCK_FLAG_IPV4))
        {
            return TUN2SOCK_E_PROTO;
        }

        size_t ipv4hdr_len = 4 * ipv4_hdr_ihl(ipv4hdr);

        if(ipv4_hdr_check_checksum(ipv4hdr) != 0)
        {
            return TUN2SOCK_E_BADPKT;
        }

        l4hdr = pkt + ipv4hdr_len;
        protocol = ipv4hdr->protocol;
        l4_len = pkt_len - ipv4hdr_len;

        saddr = ipv4hdr->src.b;
        daddr = ipv4hdr->dst.b;
    }
    else
    {
        if(!(t2s->flags & TUN2SOCK_FLAG_IPV6))
        {
            return TUN2SOCK_E_PROTO;
        }

        int next_hdr = ipv6hdr->next_hdr;
        uint8_t* next = pkt + sizeof(IPv6Header);
        l4_len = pkt_len - sizeof(IPv6Header);

        while(proto_is_ipv6_hdr_ext(next_hdr))
        {
            IPv6HeaderExtBase* base = (IPv6HeaderExtBase*)next;
            next_hdr = base->next_hdr;
            next += ipv6_hdr_ext_len(base);
            l4_len -= ipv6_hdr_ext_len(base);
        }

        l4hdr = next;
        protocol = next_hdr;

        saddr = ipv6hdr->src.b;
        daddr = ipv6hdr->dst.b;
    }

    UDPHeader* udphdr = NULL;
    TCPHeader* tcphdr = NULL;
    uint16_t sport;
    uint16_t dport;
    size_t data_len;

    switch(protocol)
    {
        case PROTO_TCP:
            tcphdr = (TCPHeader*)l4hdr;
            data_len = l4_len - 4 * tcp_hdr_dataoff(tcphdr);
            if(ipver == 4)
            {
                if(tcp4_hdr_check_checksum(saddr, daddr, tcphdr, data_len) != 0)
                {
                    return TUN2SOCK_E_BADPKT;
                }
            }
            else
            {
                if(tcp6_hdr_check_checksum(saddr, daddr, tcphdr, data_len) != 0)
                {
                    return TUN2SOCK_E_BADPKT;
                }
            }

            sport = tcphdr->sport;
            dport = tcphdr->dport;
            break;
        case PROTO_UDP:
            udphdr = (UDPHeader*)l4hdr;
            data_len = l4_len - sizeof(UDPHeader);
            if(ipver == 4)
            {
                if(udp4_hdr_check_checksum(saddr, daddr, udphdr) != 0)
                {
                    return TUN2SOCK_E_BADPKT;
                }
            }
            else
            {
                if(udp6_hdr_check_checksum(saddr, daddr, udphdr) != 0)
                {
                    return TUN2SOCK_E_BADPKT;
                }
            }

            sport = udphdr->sport;
            dport = udphdr->dport;
            break;
        default:
            return TUN2SOCK_E_PROTO;
    }

    PoolId id;
    Conn* conn;
    Conn4* conn4;
    Conn6* conn6;

    if(ipver == 4)
    {
        if(memcmp(saddr, t2s->target_addr4, 4) == 0 && sport == t2s->target_port4)
        {
            int ret = conntrack_nat_search4(ctx->track4, &id, &conn4, daddr, dport);
            if(ret != 0)
            {
                return tun2sock_error_resp(t2s, ret, 4, pkt, protocol, l4hdr);
            }
            conn = (Conn*)conn4;

            memcpy(saddr, conn4->ext_addr, 4);
            memcpy(daddr, conn4->int_addr, 4);
            sport = conn4->ext_port;
            dport = conn4->int_port;
        }
        else
        {
            int ret = conntrack_conn_search4(ctx->track4, &id, &conn4, saddr, sport, daddr, dport, CONNTRACK_CONN_SEARCH_FLAG_CREAT);
            if(ret != 0)
            {
                return tun2sock_error_resp(t2s, ret, 4, pkt, protocol, l4hdr);
            }
            conn = (Conn*)conn4;

            memcpy(saddr, conn4->ext_addr, 4);
            memcpy(daddr, t2s->target_addr4, 4);
            sport = conn4->nat_port;
            dport = t2s->target_port4;
        }

        ipv4_hdr_calc_checksum(ipv4hdr);
    }
    else
    {
        if(memcmp(saddr, t2s->target_addr6, 16) == 0 && sport == t2s->target_port6)
        {
            int ret = conntrack_nat_search6(ctx->track6, &id, &conn6, daddr, dport);
            if(ret != 0)
            {
                return tun2sock_error_resp(t2s, ret, 6, pkt, protocol, l4hdr);
            }
            conn = (Conn*)conn6;

            memcpy(saddr, conn6->ext_addr, 16);
            memcpy(daddr, conn6->int_addr, 16);
            sport = conn6->ext_port;
            dport = conn6->int_port;
        }
        else
        {
            int ret = conntrack_conn_search6(ctx->track6, &id, &conn6, saddr, sport, daddr, dport, CONNTRACK_CONN_SEARCH_FLAG_CREAT);
            if(ret != 0)
            {
                return tun2sock_error_resp(t2s, ret, 6, pkt, protocol, l4hdr);
            }
            conn = (Conn*)conn6;

            memcpy(saddr, conn6->ext_addr, 16);
            memcpy(daddr, t2s->target_addr6, 16);
            sport = conn6->nat_port;
            dport = t2s->target_port6;
        }
    }

    switch(protocol)
    {
        case PROTO_TCP:
            tcphdr->sport = sport;
            tcphdr->dport = dport;
            if(ipver == 4)
            {
                tcp4_hdr_calc_checksum(saddr, daddr, tcphdr, data_len);
            }
            else
            {
                tcp6_hdr_calc_checksum(saddr, daddr, tcphdr, data_len);
            }
            break;
        case PROTO_UDP:
            udphdr->sport = sport;
            udphdr->dport = dport;
            if(ipver == 4)
            {
                udp4_hdr_calc_checksum(saddr, daddr, udphdr);
            }
            else
            {
                udp6_hdr_calc_checksum(saddr, daddr, udphdr);
            }
            break;
    }

    if(ipver == 4)
    {
        conntrack_touch(ctx->track4, id, conn, CONN_ST_DFT);
    }
    else
    {
        conntrack_touch(ctx->track6, id, conn, CONN_ST_DFT);
    }

    return (int)pkt_len;
}

int_fast32_t tun2sock_get_original_port4(Tun2Sock* t2s, uint8_t addr[4], uint16_t port)
{
    if(t2s == NULL || t2s->internal == NULL || addr == NULL || port == 0)
    {
        return TUN2SOCK_E_INVAL;
    }

    Tun2SockCtx* ctx = t2s->internal;

    PoolId id;
    Conn4* conn4;
    int ret = conntrack_nat_search4(ctx->track4, &id, &conn4, addr, port);
    if(ret != 0)
    {
        return ret;
    }

    return conn4->ext_port;
}

int_fast32_t tun2sock_get_original_port6(Tun2Sock* t2s, uint8_t addr[16], uint16_t port)
{
    if(t2s == NULL || t2s->internal == NULL || addr == NULL || port == 0)
    {
        return TUN2SOCK_E_INVAL;
    }

    Tun2SockCtx* ctx = t2s->internal;

    PoolId id;
    Conn6* conn6;
    int ret = conntrack_nat_search6(ctx->track6, &id, &conn6, addr, port);
    if(ret != 0)
    {
        return ret;
    }

    (void)id;
    return conn6->ext_port;
}

int_fast32_t tun2sock_add_nat4(Tun2Sock* t2s, uint8_t raddr[4], uint16_t rport, uint8_t laddr[4], uint16_t lport)
{
    if(t2s == NULL || t2s->internal == NULL || raddr == NULL || rport == 0 || laddr == NULL || lport == 0)
    {
        return TUN2SOCK_E_INVAL;
    }

    Tun2SockCtx* ctx = t2s->internal;

    PoolId id;
    Conn4* conn4;
    int ret = conntrack_conn_search4(ctx->track4, &id, &conn4, laddr, lport, raddr, rport, CONNTRACK_CONN_SEARCH_FLAG_CREAT | CONNTRACK_CONN_SEARCH_FLAG_EXCL);
    if(ret != 0)
    {
        return ret;
    }

    conntrack_touch(ctx->track4, id, (Conn*)conn4, CONN_ST_DFT);
    return 0;
}

int_fast32_t tun2sock_add_nat6(Tun2Sock* t2s, uint8_t raddr[16], uint16_t rport, uint8_t laddr[16], uint16_t lport)
{
    if(t2s == NULL || t2s->internal == NULL || raddr == NULL || rport == 0 || laddr == NULL || lport == 0)
    {
        return TUN2SOCK_E_INVAL;
    }

    Tun2SockCtx* ctx = t2s->internal;

    PoolId id;
    Conn6* conn6;
    int ret = conntrack_conn_search6(ctx->track6, &id, &conn6, laddr, lport, raddr, rport, CONNTRACK_CONN_SEARCH_FLAG_CREAT | CONNTRACK_CONN_SEARCH_FLAG_EXCL);
    if(ret != 0)
    {
        return ret;
    }

    conntrack_touch(ctx->track6, id, (Conn*)conn6, CONN_ST_DFT);
    return 0;
}
