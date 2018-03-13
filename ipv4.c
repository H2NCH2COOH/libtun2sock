#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "ipv4.h"

int ipv4_aton(const char* str, IPv4Addr* addr)
{
    const char* DIGIT = "0123456789";

    IPv4Addr saddr;

    int i = 0;
    int b = 0;
    char s = 'i';
    while(1)
    {
        switch(s)
        {
            case 'd':
                if(*str == '.')
                {
                    if(i > 3)
                    {
                        return -1;
                    }

            case 'e':
                    if(b > 255)
                    {
                        return -1;
                    }
                    saddr.b[i++] = b;
                    b = 0;

                    if(s == 'e')
                    {
                        goto out;
                    }

                    s = 'i';
                    break;
                }
                /* fall-through */
            case 'i':
                if(!isdigit(*str))
                {
                    return -1;
                }

                s = 'd';
                b *= 10;
                b += strchr(DIGIT, *str) - DIGIT;
                break;
        }

        ++str;
        if(*str == '\0')
        {
            if(s != 'd' || i != 3)
            {
                return -1;
            }
            s = 'e';
        }
    }

    return -1;

out:
    memcpy(addr, &saddr, sizeof(saddr));
    return 0;
}

const char* ipv4_ntoa(IPv4Addr* addr)
{
    static char buff[16];
    snprintf(buff, sizeof(buff), "%d.%d.%d.%d", addr->b[0], addr->b[1], addr->b[2], addr->b[3]);
    return buff;
}

int ipv4_hdr_calc_checksum(IPv4Header* hdr)
{
    uint32_t sum = 0;
    hdr->checksum = 0;

    uint16_t* p = (uint16_t*)hdr;
    int i;
    int l = ipv4_hdr_ihl(hdr) * 2;
    for(i = 0; i < l; ++i)
    {
        sum += *p++;
    }

    while(sum > 0xFFFF)
    {
        sum = (sum & 0xFFFF) + ((sum & 0xFFFF0000) >> 16);
    }

    hdr->checksum = (sum & 0xFFFF) ^ 0xFFFF;

    return 0;
}

int ipv4_hdr_check_checksum(IPv4Header* hdr)
{
    uint32_t sum = 0;

    uint16_t* p = (uint16_t*)hdr;
    int i;
    int l = ipv4_hdr_ihl(hdr) * 2;
    for(i = 0; i < l; ++i)
    {
        sum += *p++;
    }

    while(sum > 0xFFFF)
    {
        sum = (sum & 0xFFFF) + ((sum & 0xFFFF0000) >> 16);
    }

    return (sum == 0xFFFF)? 0 : -1;
}
