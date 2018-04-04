#include <string.h>
#include "protocol.h"
#include "icmp.h"

static uint16_t icmp_hdr_checksum(uint8_t* fake_hdr, unsigned int fake_hdr_len, ICMPHeader* hdr, uint16_t data_len)
{
    uint32_t sum = 0;
    unsigned int i;
    unsigned int l = sizeof(ICMPHeader) + data_len;
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

    if(fake_hdr != NULL)
    {
        p = (uint16_t*)fake_hdr;
        for(i = 0; i < (fake_hdr_len >> 1); ++i)
        {
            sum += *p++;
        }
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

static uint16_t icmp4_hdr_checksum(ICMPHeader* hdr, uint16_t data_len)
{
    return icmp_hdr_checksum(NULL, 0, hdr, data_len);
}

static uint16_t icmp6_hdr_checksum(uint8_t src[4], uint8_t dst[4], ICMPHeader* hdr, uint16_t data_len)
{
    struct
    {
        uint8_t src[16];
        uint8_t dst[16];
        uint8_t len[4];
        uint8_t zero[3];
        uint8_t next_hdr;
    } fake_hdr;

    uint32_t l = sizeof(ICMPHeader) + data_len;

    memcpy(fake_hdr.src, src, 16);
    memcpy(fake_hdr.dst, dst, 16);
    fake_hdr.len[0] = (l >> 24) & 0xFF;
    fake_hdr.len[1] = (l >> 16) & 0xFF;
    fake_hdr.len[2] = (l >> 8) & 0xFF;
    fake_hdr.len[3] = (l >> 0) & 0xFF;
    fake_hdr.zero[0] = 0;
    fake_hdr.zero[1] = 0;
    fake_hdr.zero[2] = 0;
    fake_hdr.next_hdr = PROTO_IPv6_ICMP;

    return icmp_hdr_checksum((uint8_t*)&fake_hdr, sizeof(fake_hdr), hdr, data_len);
}

void icmp4_hdr_calc_checksum(ICMPHeader* hdr, uint16_t data_len)
{
    hdr->checksum = 0;
    uint16_t cs = icmp4_hdr_checksum(hdr, data_len);
    hdr->checksum = cs;
}

void icmp6_hdr_calc_checksum(uint8_t src[16], uint8_t dst[16], ICMPHeader* hdr, uint32_t data_len)
{
    hdr->checksum = 0;
    uint16_t cs = icmp6_hdr_checksum(src, dst, hdr, data_len);
    hdr->checksum = cs;
}

int icmp4_hdr_check_checksum(ICMPHeader* hdr, uint16_t data_len)
{
    uint16_t cs = icmp4_hdr_checksum(hdr, data_len);
    return (cs == 0)? 0 : -1;
}

int icmp6_hdr_check_checksum(uint8_t src[16], uint8_t dst[16], ICMPHeader* hdr, uint32_t data_len)
{
    uint16_t cs = icmp6_hdr_checksum(src, dst, hdr, data_len);
    return (cs == 0)? 0 : -1;
}
