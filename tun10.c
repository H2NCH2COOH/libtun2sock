#define _GNU_SOURCE
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
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

int main(int argc, char** argv)
{
    errno = 0;
    int fd = tun_alloc("tun10");
    if(fd < 0)
    {
        printf("TUN alloction failed with error: %s\n", strerror(errno));
        return 1;
    }

    system("ip addr add 10.99.99.1/24 dev tun10");
    system("ip link set dev tun10 mtu 1500");
    system("ip link set dev tun10 up");

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

        void* ptr = (void*)buff;
        IPv4Header* iphdr = ptr;
        int iphdr_len = 4 * ipv4_hdr_ihl(iphdr);
        printf("IPv4: version: %u ihl: %u len: %u protocol: %u\n", ipv4_hdr_version(iphdr), ipv4_hdr_ihl(iphdr), ntohs(iphdr->len), iphdr->protocol);

        if(ipv4_hdr_check_checksum(iphdr) != 0)
        {
            printf("Bad IPv4 checksum\n");
            return 1;
        }

        TCPHeader* tcphdr;
        UDPHeader* udphdr;
        char* data;
        int data_len;
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
                data_len = ret - iphdr_len - tcphdr_len;
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
                    ntohs(udphdr->len),
                    ntohs(udphdr->checksum)
                );
                data = ptr + iphdr_len + sizeof(UDPHeader);
                data_len = ret - iphdr_len - sizeof(UDPHeader);
                if(udp4_hdr_check_checksum(iphdr->src.b, iphdr->dst.b, udphdr, data_len) != 0)
                {
                    printf("Bad UDP checksum\n");
                    return 1;
                }

                break;
        }

        printf("Data length: %d\n", data_len);
    }

    close(fd);
    return 0;
}
