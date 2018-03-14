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
 * @param hdr Pointer to a UDPHeader
 * @return 0 for success, -1 for failure
 */
int udp_hdr_calc_checksum(UDPHeader* hdr);

/***
 * Check the checksum of UDP header
 * @param hdr Pointer to a UDPHeader
 * @return 0 for success, -1 for failure
 */
int udp_hdr_check_checksum(UDPHeader* hdr);


#endif /* _UDP_H_ */
