#define _GNU_SOURCE
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "protocol.h"
#include "ipv4.h"
#include "ipv6.h"
#include "tcp.h"
#include "udp.h"
#include "tun2sock.h"

int tun_alloc(const char* dev)
{
    struct ifreq ifr;
    int fd;

    fd = open("/dev/net/tun", O_RDWR);
    if(fd < 0)
    {
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if(*dev)
    {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if(ioctl(fd, TUNSETIFF, (void *)&ifr) != 0)
    {
        close(fd);
        return -1;
    }

    if(strcmp(dev, ifr.ifr_name) != 0)
    {
        printf("Changed TUN ifname: %s (req: %s)\n", ifr.ifr_name, dev);
    }

    return fd;
}

static int print_pkt(char* buff, int len)
{
    void* ptr = (void*)buff;
    IPv4Header* iphdr = ptr;

    if(ipv4_hdr_version(iphdr) != 4)
    {
        printf("Bad version: %u\n", ipv4_hdr_version(iphdr));
        return 1;
    }

    int iphdr_len = 4 * ipv4_hdr_ihl(iphdr);
    printf("IPv4: version: %u ihl: %u len: %u protocol: %u\n", ipv4_hdr_version(iphdr), ipv4_hdr_ihl(iphdr), ipv4_hdr_len(iphdr), iphdr->protocol);
    printf("Src: %s\n", ipv4_ntoa(&iphdr->src));
    printf("Dst: %s\n", ipv4_ntoa(&iphdr->dst));

    if(ipv4_hdr_check_checksum(iphdr) != 0)
    {
        printf("Bad IPv4 checksum\n");
        return 1;
    }

    TCPHeader* tcphdr;
    UDPHeader* udphdr;
    char* data;
    int data_len = 0;
    switch(iphdr->protocol)
    {
        case PROTO_TCP:
            tcphdr = ptr + iphdr_len;
            int tcphdr_len = 4 * tcp_hdr_dataoff(tcphdr);

            uint16_t flags = tcp_hdr_flags(tcphdr);
            printf("TCP: sport: %u dport: %u seq: %u ack: %u win: %u dataoff: %u flags: %X\n",
                ntohs(tcphdr->sport),
                ntohs(tcphdr->dport),
                ntohl(tcphdr->seq),
                ntohl(tcphdr->ack),
                ntohs(tcphdr->win),
                tcp_hdr_dataoff(tcphdr),
                flags
            );

            data = ptr + iphdr_len + tcphdr_len;
            data_len = len - iphdr_len - tcphdr_len;
            if(tcp4_hdr_check_checksum(iphdr->src.b, iphdr->dst.b, tcphdr, data_len) != 0)
            {
                printf("Bad TCP checksum\n");
                return 1;
            }

            break;
        case PROTO_UDP:
            udphdr = ptr + iphdr_len;
            printf("UDP: sport: %u dport: %u len: %u checksum: %x\n",
                ntohs(udphdr->sport),
                ntohs(udphdr->dport),
                udp_hdr_len(udphdr),
                ntohs(udphdr->checksum)
            );
            data = ptr + iphdr_len + sizeof(UDPHeader);
            data_len = len - iphdr_len - sizeof(UDPHeader);
            if(udp4_hdr_check_checksum(iphdr->src.b, iphdr->dst.b, udphdr) != 0)
            {
                printf("Bad UDP checksum\n");
                return 1;
            }

            break;
        default:
            printf("Unknown protocol: %u", iphdr->protocol);
            break;
    }

    printf("Data length: %d\n", data_len);
    (void)data;

    printf("\n");

    return 0;
}

static uint32_t time2()
{
    return (uint32_t)time(NULL);
}

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    errno = 0;
    int fd = tun_alloc("tun10");
    if(fd < 0)
    {
        printf("TUN alloction failed with error: %s\n", strerror(errno));
        return 1;
    }

    int ff = system("ip addr add 10.99.99.1/24 dev tun10");
    ff = system("ip link set dev tun10 mtu 1500");
    ff = system("ip link set dev tun10 up");
    ff = system("ip route add 25.0.0.0/16 dev tun10");
    (void)ff;

    Tun2Sock t2s = {
        .realloc = realloc,
        .time = time2,
        .flags = TUN2SOCK_FLAG_IPV4,
        .target_addr4 = {10, 99, 99, 1},
        .target_port4 = htons(12345),
        .timeout = 30,
        .max_connections_bits = 10,
        .internal = NULL,
    };

    int err = tun2sock_init(&t2s);
    if(err != 0)
    {
        printf("Faild to init tun2sock with error: (%d)%s\n", err, tun2sock_strerr(err));
        return 1;
    }

    char buff[1600];

    while(1)
    {
        int ret = read(fd, buff, sizeof(buff));
        if(ret < 0)
        {
            printf("Failed to read packet with error: %s\n", strerror(errno));
            return 1;
        }

        printf("Read packet with length: %d\n", ret);
        if(print_pkt(buff, ret) != 0)
        {
            return 1;
        }

        ret = tun2sock_input(&t2s, buff);

        if(ret > 0)
        {
            printf("Tun2Sock returned a packet with length: %d\n", ret);
            if(print_pkt(buff, ret) != 0)
            {
                return 1;
            }

            if(write(fd, buff, ret) <= 0)
            {
                printf("Failed to write packet with error: %s\n", strerror(errno));
                return 1;
            }
        }
        else
        {
            printf("Tun2Sock returned error: (%d)%s\n", ret, tun2sock_strerr(ret));
        }
    }

    close(fd);
    return 0;
}
