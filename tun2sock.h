#ifndef _TUN2SOCK_H_
#define _TUN2SOCK_H_

/***
 * This is a lib to convert a TUN interface into socket operation
 *
 * First the user should create listening socket for TCP and UDP
 * at the same address: [A0:P0] which is called target address
 *
 * Then the user should route traffic to the TUN interface
 *
 * Then the user can read packet from the TUN interface and input it to this lib
 * This lib will either tell the user to drop the packet or
 * modifys it and tell the user to send it back to the TUN interface
 *
 * Then the user should receive the traffic in the listening socket with
 * destination address as [A0:P0] and source address allocated by this lib, called NAT address
 * The NAT address has the SAME IP address as the original destination and a allocated port
 *
 * Then the user can use the NAT address to get the original destination address from this lib
 * and do what ever to the traffic on a socket level
 *
 * A full process:
 *
 *  Local[A1:P1] --socket-> (Remote[A2:P2]) --route-> TUN --program-> Tun2Sock[A1:P1:A2:P2]  --+
 *                                                                                             |
 * Target[A0:P0] <-socket--      ([A2:P2']) <-route-- TUN <-program-- Tun2Sock[A2:P2':A0:P0] <-+
 *
 * [A2:P2'] -> Tun2Sock -> [A2:P2]
 * ...
 *
 * Target[A0:P0] --socket->      ([A2:P2']) --route-> TUN --program-> Tun2Sock[A0:P0:A2:P2'] --+
 *                                                                                             |
 *  Local[A1:P1] <-socket-- (Remote[A2:P2]) <-route-- TUN <-program-- Tun2Sock[A2:P2:A1:P1]  <-+
 */

#include <stdint.h>

/***
 * Flag items
 */
#define TUN2SOCK_FLAG_IPV4                  1 //Support IPv4
#define TUN2SOCK_FLAG_IPV6                  2 //Support IPv6

/***
 * Error numbers
 */
#define TUN2SOCK_E_SUCCESS      0

#define TUN2SOCK_E_INVAL        -1
#define TUN2SOCK_E_NOMEM        -2

#define TUN2SOCK_E_DRPPKT       -20 //The packet should be dropped (No reason and no error)
#define TUN2SOCK_E_BADPKT       -21 //The packet is invalid (e.g. Bad checksum)
#define TUN2SOCK_E_PROTO        -22 //Unsupported protocol (e.g. ICMP)

#define TUN2SOCK_E_CTNFND       -30 //Address not found in connection track
#define TUN2SOCK_E_CTFULL       -31 //Connection track full

typedef struct Tun2Sock_s Tun2Sock;
struct Tun2Sock_s
{
    /***
     * stdlib realloc like
     */
    void* (*realloc)(void* ptr, int size);

    /***
     * The number of seconds elapsed from a monotonic clock
     */
    uint32_t (*time)();

    /***
     * TUN2SOCK_FLAG_* ORed
     */
    int flags;

    /***
     * The IPv4 target address and port
     * !NOTE: the port should be in network order
     */
    uint8_t target_addr4[4];
    uint16_t target_port4;

    /***
     * The IPv6 target address and port
     * !NOTE: the port should be in network order
     */
    uint8_t target_addr6[16];
    uint16_t target_port6;

    /***
     * Internal data attached during execution
     * Do not touch
     */
    void* internal;
};

/***
 * Init
 * @param t2s       The Tun2Sock struct
 * @return          0  Success
 *                  <0 Error number (TUN2SOCK_E_*)
 */
int tun2sock_init(Tun2Sock* t2s);

/***
 * Cleanup
 * @param t2s       The Tun2Sock struct
 */
void tun2sock_cleanup(Tun2Sock* t2s);

/***
 * Return a static string for the error number
 * The string is immutable and always valid
 * @param           The error number
 * @return          The string
 */
const char* tun2sock_strerr(int err);

/***
 * Input a packet
 * This function should be called when a IP(v4/v6) packet is received from the tun
 * This function will decide if the packet should be dropped or modified and send back to the tun
 * This function will only modify the IP & TCP/UDP header
 * @param t2s       The Tun2Sock struct
 * @param pkt       The packet (Need to be a valid IP packet and mutable)
 * @return          0  The packet is modified and should be send back to the tun
 *                  <0 Error number, and the packet shoud be dropped
 */
int tun2sock_input(Tun2Sock* t2s, char* pkt);

/***
 * Get the original destination port using the NAT address
 * !NOTE: The port returned is in network order
 * Choose the right function based on protocol
 * @param t2s       The Tun2Sock struct
 * @param addr      The IP address
 * @param port      The port
 * @return          >0 The original port
 *                  <0 Error number
 */
int_fast32_t tun2sock_get_original_port_udp4(Tun2Sock* t2s, uint8_t addr[4], uint16_t port);
int_fast32_t tun2sock_get_original_port_tcp4(Tun2Sock* t2s, uint8_t addr[4], uint16_t port);
int_fast32_t tun2sock_get_original_port_udp6(Tun2Sock* t2s, uint8_t addr[16], uint16_t port);
int_fast32_t tun2sock_get_original_port_tcp6(Tun2Sock* t2s, uint8_t addr[16], uint16_t port);

/***
 * Add a entry to NAT table
 * Using the following functions, the user can supply a remote address A2:P2, a local address A1:P1
 * The function will return a port P2'
 * The user can then send TCP/UDP traffic to [A2:P2'] (A2 should route to the TUN) from the target address and the traffic will be redirected to [A1:P1] with source address as [A2:P2]
 * These functions is mainly used to let a remote peer to connect to a local program
 * !NOTE: The port returned is in network order
 * @param t2s       The Tun2Sock struct
 * @param raddr     The remote IP address
 * @param rport     The remote port
 * @param laddr     The local IP address
 * @param lport     The local port
 * @return          >0 The allocated remote port
 *                  <0 Error number
 */
int_fast32_t tun2sock_add_nat_udp4(Tun2Sock* t2s, uint8_t raddr[4], uint16_t rport, uint8_t laddr[4], uint16_t lport);
int_fast32_t tun2sock_add_nat_tcp4(Tun2Sock* t2s, uint8_t raddr[4], uint16_t rport, uint8_t laddr[4], uint16_t lport);
int_fast32_t tun2sock_add_nat_udp6(Tun2Sock* t2s, uint8_t raddr[16], uint16_t rport, uint8_t laddr[16], uint16_t lport);
int_fast32_t tun2sock_add_nat_tcp6(Tun2Sock* t2s, uint8_t raddr[16], uint16_t rport, uint8_t laddr[16], uint16_t lport);

#endif /* _TUN2SOCK_H_ */
