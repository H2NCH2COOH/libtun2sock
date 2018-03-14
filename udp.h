#ifndef _UDP_H_
#define _UDP_H_

#include <stdint.h>

typedef struct
{
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t checksum;
} UDPHeader;

/***
 * Calculate and set the checksum of UDP header
 * @param src The source IPv4/6 address
 * @param dst The destination IPv4/6 address
 * @param hdr Pointer to a UDPHeader and following data
 * @param data_len The length of UDP data
 * @return 0 for success, -1 for failure
 */
int udp4_hdr_calc_checksum(uint8_t src[4], uint8_t dst[4], UDPHeader* hdr, uint16_t data_len);
int udp6_hdr_calc_checksum(uint8_t src[16], uint8_t dst[16], UDPHeader* hdr, uint32_t data_len);

/***
 * Check the checksum of UDP header
 * @param src The source IPv4/6 address
 * @param dst The destination IPv4/6 address
 * @param hdr Pointer to a UDPHeader and following data
 * @param data_len The length of UDP data
 * @return 0 for success, -1 for failure
 */
int udp4_hdr_check_checksum(uint8_t src[4], uint8_t dst[4], UDPHeader* hdr, uint16_t data_len);
int udp6_hdr_check_checksum(uint8_t src[16], uint8_t dst[16], UDPHeader* hdr, uint32_t data_len);

#endif /* _UDP_H_ */
