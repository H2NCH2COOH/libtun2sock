#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdint.h>
#include <limits.h>

static inline uint16_t sum16(const uint8_t* arr, unsigned int cnt)
{
#if (UINT_MAX == UINT32_MAX)
    uint32_t sum = 0;
    const uint32_t* p = (const uint32_t*)arr;
    while(cnt >= 4)
    {
        uint32_t s = *p++;
        sum += s;
        if(sum < s)
        {
            ++sum;
        }
        cnt -= 4;
    }

    arr = (const uint8_t*)p;

    if(cnt & 2)
    {
        uint16_t s = *(const uint16_t*)arr;
        sum += s;
        if(sum < s)
        {
            ++sum;
        }
        arr += 2;
    }

    if(cnt & 1)
    {
        uint8_t b = *arr;
        sum += b;
        if(sum < b)
        {
            ++sum;
        }
    }

    uint16_t s0 = sum;
    uint16_t s1 = sum >> 16;
    s0 += s1;
    if(s0 < s1)
    {
        ++s0;
    }
    return s0;
#elif (UINT_MAX == UINT64_MAX)
    uint64_t sum = 0;
    const uint64_t* p = (const uint64_t*)arr;
    while(cnt >= 8)
    {
        uint64_t s = *p++;
        sum += s;
        if(sum < s)
        {
            ++sum;
        }
        cnt -= 8;
    }

    arr = (const uint8_t*)p;

    if(cnt & 4)
    {
        uint32_t w = *(const uint32_t*)arr;
        sum += w;
        if(sum < w)
        {
            ++sum;
        }
        arr += 4;
    }

    if(cnt & 2)
    {
        uint16_t s = *(const uint16_t*)arr;
        sum += s;
        if(sum < s)
        {
            ++sum;
        }
        arr += 2;
    }

    if(cnt & 1)
    {
        uint8_t b = *arr;
        sum += b;
        if(sum < b)
        {
            ++sum;
        }
    }

    uint32_t w0 = sum;
    uint32_t w1 = sum >> 32;
    w0 += w1;
    if(w0 < w1)
    {
        ++w0;
    }
    uint16_t s0 = w0;
    uint16_t s1 = w0 >> 16;
    s0 += s1;
    if(s0 < s1)
    {
        ++s0;
    }
    return s0;
#else
#warning "Using 16-bit sum"
    uint16_t sum = 0;
    const uint16_t* p = (const uint16_t*)arr;

    while(cnt >= 2)
    {
        uint16_t s = *p++;
        sum += s;
        if(sum < s)
        {
            ++sum;
        }
        cnt -= 2;
    }

    arr = (const uint8_t*)p;

    if(cnt)
    {
        uint8_t b = *arr;
        sum += b;
        if(sum < b)
        {
            ++sum;
        }
    }

    return sum;
#endif
}

#endif /* _UTIL_H_ */
