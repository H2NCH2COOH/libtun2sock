#include <string.h>
#include "protocol.h"
#include "udp.h"

static uint16_t udp_hdr_checksum(uint8_t* fake_hdr, unsigned int fake_hdr_len, UDPHeader* hdr, uint16_t data_len)
{
    uint32_t sum = 0;
    unsigned int i;
    unsigned int l = sizeof(UDPHeader) + data_len;
    uint16_t* p;
    uint8_t last_word[2];

    last_word[0] = 0;
    last_word[1] = 0;

    if(data_len & 1)
    {
        last_word[0] = *(((uint8_t*)hdr) + l - 1);
        --data_len;
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

static uint16_t udp4_hdr_checksum(uint8_t src[4], uint8_t dst[4], UDPHeader* hdr, uint16_t data_len)
{
    struct
    {
        uint8_t src[4];
        uint8_t dst[4];
        uint8_t zero;
        uint8_t proto;
        uint8_t len[2];
    } fake_hdr;

    uint16_t l = sizeof(UDPHeader) + data_len;

    memcpy(fake_hdr.src, src, 4);
    memcpy(fake_hdr.dst, dst, 4);
    fake_hdr.zero = 0;
    fake_hdr.proto = PROTO_UDP;
    fake_hdr.len[0] = (l >> 8) & 0xFF;
    fake_hdr.len[1] = (l >> 0) & 0xFF;

    return udp_hdr_checksum((uint8_t*)&fake_hdr, sizeof(fake_hdr), hdr, data_len);
}

static uint16_t udp6_hdr_checksum(uint8_t src[4], uint8_t dst[4], UDPHeader* hdr, uint16_t data_len)
{
    struct
    {
        uint8_t src[16];
        uint8_t dst[16];
        uint8_t len[4];
        uint8_t zero[3];
        uint8_t next_hdr;
    } fake_hdr;

    uint32_t l = sizeof(UDPHeader) + data_len;

    memcpy(fake_hdr.src, src, 16);
    memcpy(fake_hdr.dst, dst, 16);
    fake_hdr.len[0] = (l >> 24) & 0xFF;
    fake_hdr.len[1] = (l >> 16) & 0xFF;
    fake_hdr.len[2] = (l >> 8) & 0xFF;
    fake_hdr.len[3] = (l >> 0) & 0xFF;
    fake_hdr.zero[0] = 0;
    fake_hdr.zero[1] = 0;
    fake_hdr.zero[2] = 0;
    fake_hdr.next_hdr = PROTO_UDP;

    return udp_hdr_checksum((uint8_t*)&fake_hdr, sizeof(fake_hdr), hdr, data_len);
}

int udp4_hdr_calc_checksum(uint8_t src[4], uint8_t dst[4], UDPHeader* hdr, uint16_t data_len)
{
    hdr->checksum = 0;
    uint16_t cs = udp4_hdr_checksum(src, dst, hdr, data_len);
    if(cs == 0)
    {
        cs = 0xFFFF;
    }
    hdr->checksum = cs;
    return 0;
}

int udp6_hdr_calc_checksum(uint8_t src[16], uint8_t dst[16], UDPHeader* hdr, uint32_t data_len)
{
    hdr->checksum = 0;
    uint16_t cs = udp6_hdr_checksum(src, dst, hdr, data_len);
    if(cs == 0)
    {
        cs = 0xFFFF;
    }
    hdr->checksum = cs;
    return 0;
}

int udp4_hdr_check_checksum(uint8_t src[4], uint8_t dst[4], UDPHeader* hdr, uint16_t data_len)
{
    if(hdr->checksum == 0)
    {
        return 0;
    }
    uint16_t cs = udp4_hdr_checksum(src, dst, hdr, data_len);
    return (cs == 0)? 0 : -1;
}

int udp6_hdr_check_checksum(uint8_t src[16], uint8_t dst[16], UDPHeader* hdr, uint32_t data_len)
{
    if(hdr->checksum == 0)
    {
        return -1;
    }
    uint16_t cs = udp6_hdr_checksum(src, dst, hdr, data_len);
    return (cs == 0)? 0 : -1;
}
