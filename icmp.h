#ifndef _ICMP_H_
#define _ICMP_H_

#include <stdint.h>

typedef struct
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t zero;
} ICMPHeader;

/***
 * Calculate and set the checksum of ICMP header
 * @param src The source IPv4/6 address
 * @param dst The destination IPv4/6 address
 * @param hdr Pointer to an ICMPHeader and following data
 * @param data_len The length of ICMP data
 */
void icmp4_hdr_calc_checksum(uint8_t src[4], uint8_t dst[4], ICMPHeader* hdr, uint16_t data_len);
void icmp6_hdr_calc_checksum(uint8_t src[16], uint8_t dst[16], ICMPHeader* hdr, uint32_t data_len);

/***
 * Check the checksum of ICMP header
 * @param src The source IPv4/6 address
 * @param dst The destination IPv4/6 address
 * @param hdr Pointer to an ICMPHeader and following data
 * @param data_len The length of ICMP data
 * @return 0 for success, -1 for failure
 */
int icmp4_hdr_check_checksum(uint8_t src[4], uint8_t dst[4], ICMPHeader* hdr, uint16_t data_len);
int icmp6_hdr_check_checksum(uint8_t src[16], uint8_t dst[16], ICMPHeader* hdr, uint32_t data_len);

#endif /* _ICMP_H_ */
