#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "ipv6.h"

/***
 * "xxxx:xxxx:xxxx::xxxx:xxxx:xxxx" -> IPv6Addr
 * @param str NUL terminated string
 * @param addr Pointer to a IPv6Addr
 * @return 0 for success, -1 for failure
 */
int ipv6_aton(const char* str, IPv6Addr* addr)
{
    const char* XDIGIT = "0123456789abcdef";

    uint32_t d = 0;
    int i = 0;
    int blank = -1;
    char s = 'i';
    uint16_t buf[8];

    while(1)
    {
        switch(s)
        {
            case 's':
                if(*str == ':')
                {
                    if(blank > 0)
                    {
                        return -1;
                    }

                    blank = i;
                    break;
                }
                s = 'i';
                /* fall-through */
            case 'i':
                if(*str == ':')
                {
            case 'e':
                    if(i + (blank > 0) > 7)
                    {
                        return -1;
                    }

                    if(d > 0xFFFF)
                    {
                        return -1;
                    }

                    buf[i] = d;
                    ++i;
                    d = 0;

                    if(s == 'e')
                    {
                        goto out;
                    }

                    s = 's';
                    break;
                }

                if(!isxdigit(*str))
                {
                    return -1;
                }

                d <<= 4;
                d |= strchr(XDIGIT, tolower(*str)) - XDIGIT;
                break;
        }

        ++str;
        if(*str == '\0')
        {
            if(s != 'i' && s != 's')
            {
                return -1;
            }
            s = 'e';
        }
    }

out:
    if(blank > 0)
    {
        int j = 8 - i;
        memmove(buf + j + blank, buf + blank, sizeof(uint16_t) * (i - blank));
        memset(buf + blank, 0, sizeof(uint16_t) * j);
        i = 8;
    }

    if(i != 8)
    {
        return -1;
    }

    for(i = 0; i < 8; ++i)
    {
        addr->b[i << 1] = (buf[i] & 0xFF00) >> 8;
        addr->b[(i << 1) | 1] = buf[i] & 0xFF;
    }

    return 0;
}

/***
 * IPv6Addr -> "xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx"
 * @param addr Pointer to a IPv6Addr
 * @return A NUL terminated string within a static buffer
 */
const char* ipv6_ntoa(IPv6Addr* addr)
{
    static char buff[40];

    snprintf(buff, sizeof(buff), "%x:%x:%x:%x:%x:%x:%x:%x",
        addr->b[0] << 8 | addr->b[1],
        addr->b[2] << 8 | addr->b[3],
        addr->b[4] << 8 | addr->b[5],
        addr->b[6] << 8 | addr->b[7],
        addr->b[8] << 8 | addr->b[9],
        addr->b[10] << 8 | addr->b[11],
        addr->b[12] << 8 | addr->b[13],
        addr->b[14] << 8 | addr->b[15]
    );
    return buff;
}

