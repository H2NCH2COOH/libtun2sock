#include <string.h>
#include "protocol.h"
#include "udp.h"

static uint16_t udp_hdr_checksum(uint8_t* fake_hdr, unsigned int fake_hdr_len, UDPHeader* hdr)
{
    uint32_t sum = 0;
    unsigned int i;
    unsigned int l = (hdr->len[0] << 8) | hdr->len[1];
    uint16_t* p;
    uint8_t last_word[2];

    last_word[0] = 0;
    last_word[1] = 0;

    if(l & 1)
    {
        last_word[0] = *(((uint8_t*)hdr) + l - 1);
        --l;
    }

    p = (uint16_t*)fake_hdr;
    for(i = 0; i < (fake_hdr_len >> 1); ++i)
    {
        sum += *p++;
    }

    p = (uint16_t*)hdr;
    for(i = 0; i < (l >> 1); ++i)
    {
        sum += *p++;
    }

    p = (uint16_t*)last_word;
    sum += *p;

    while(sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

static uint16_t udp4_hdr_checksum(uint8_t src[4], uint8_t dst[4], UDPHeader* hdr)
{
    struct
    {
        uint8_t src[4];
        uint8_t dst[4];
        uint8_t zero;
        uint8_t proto;
        uint8_t len[2];
    } fake_hdr;

    memcpy(fake_hdr.src, src, 4);
    memcpy(fake_hdr.dst, dst, 4);
    fake_hdr.zero = 0;
    fake_hdr.proto = PROTO_UDP;
    fake_hdr.len[0] = hdr->len[0];
    fake_hdr.len[1] = hdr->len[1];

    return udp_hdr_checksum((uint8_t*)&fake_hdr, sizeof(fake_hdr), hdr);
}

static uint16_t udp6_hdr_checksum(uint8_t src[4], uint8_t dst[4], UDPHeader* hdr)
{
    struct
    {
        uint8_t src[16];
        uint8_t dst[16];
        uint8_t len[4];
        uint8_t zero[3];
        uint8_t next_hdr;
    } fake_hdr;

    memcpy(fake_hdr.src, src, 16);
    memcpy(fake_hdr.dst, dst, 16);
    fake_hdr.len[0] = 0;
    fake_hdr.len[1] = 0;
    fake_hdr.len[2] = hdr->len[0];
    fake_hdr.len[3] = hdr->len[1];
    fake_hdr.zero[0] = 0;
    fake_hdr.zero[1] = 0;
    fake_hdr.zero[2] = 0;
    fake_hdr.next_hdr = PROTO_UDP;

    return udp_hdr_checksum((uint8_t*)&fake_hdr, sizeof(fake_hdr), hdr);
}

void udp4_hdr_calc_checksum(uint8_t src[4], uint8_t dst[4], UDPHeader* hdr)
{
    hdr->checksum = 0;
    uint16_t cs = udp4_hdr_checksum(src, dst, hdr);
    if(cs == 0)
    {
        cs = 0xFFFF;
    }
    hdr->checksum = cs;
}

void udp6_hdr_calc_checksum(uint8_t src[16], uint8_t dst[16], UDPHeader* hdr)
{
    hdr->checksum = 0;
    uint16_t cs = udp6_hdr_checksum(src, dst, hdr);
    if(cs == 0)
    {
        cs = 0xFFFF;
    }
    hdr->checksum = cs;
}

int udp4_hdr_check_checksum(uint8_t src[4], uint8_t dst[4], UDPHeader* hdr)
{
    if(hdr->checksum == 0)
    {
        return 0;
    }
    uint16_t cs = udp4_hdr_checksum(src, dst, hdr);
    return (cs == 0)? 0 : -1;
}

int udp6_hdr_check_checksum(uint8_t src[16], uint8_t dst[16], UDPHeader* hdr)
{
    if(hdr->checksum == 0)
    {
        return -1;
    }
    uint16_t cs = udp6_hdr_checksum(src, dst, hdr);
    return (cs == 0)? 0 : -1;
}
