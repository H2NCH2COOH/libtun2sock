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
 * If some error occured, the lib may modify the packet into some error response (ICMP/TCP RST)
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
 * Target[A0:P0] <-socket--   (NAT[A2:P2']) <-route-- TUN <-program-- Tun2Sock[A2:P2':A0:P0] <-+
 *
 * [A2:P2'] -> Tun2Sock -> [A2:P2]
 * ...
 *
 * Target[A0:P0] --socket->   (NAT[A2:P2']) --route-> TUN --program-> Tun2Sock[A0:P0:A2:P2'] --+
 *                                                                                             |
 *  Local[A1:P1] <-socket-- (Remote[A2:P2]) <-route-- TUN <-program-- Tun2Sock[A2:P2:A1:P1]  <-+
 */

#include <stddef.h>
#include <stdint.h>

/***
 * Flag items
 */
#define TUN2SOCK_FLAG_IPV4                  1 //Support IPv4
#define TUN2SOCK_FLAG_IPV6                  2 //Support IPv6
#define TUN2SOCK_FLAG_NO_ICMP_ERR_RSP       4 //Do not return ICMP destination unreachable when denying a packet
#define TUN2SOCK_FLAG_NO_TCP_RST_ERR_RSP    8 //Do not return TCP RST when denying a TCP packet (Will use ICMP if allowed)

/***
 * Error numbers
 */
#define TUN2SOCK_E_SUCCESS      0

#define TUN2SOCK_E_INVAL        -1
#define TUN2SOCK_E_NOMEM        -2
#define TUN2SOCK_E_INTERNAL     -3 //Internal error

#define TUN2SOCK_E_DRPPKT       -20 //The packet should be dropped (No reason and no error)
#define TUN2SOCK_E_BADPKT       -21 //The packet is invalid (e.g. Bad checksum)
#define TUN2SOCK_E_PROTO        -22 //Unsupported protocol (e.g. ICMP)

#define TUN2SOCK_E_NOCONN       -30 //Connection not found
#define TUN2SOCK_E_NONAT        -31 //NAT not found
#define TUN2SOCK_E_MAXCONN      -32 //Reached maximum connections
#define TUN2SOCK_E_MAXNAT       -33 //No more port for NAT
#define TUN2SOCK_E_EXTCONN      -34 //A connection already exists

typedef struct Tun2Sock_s Tun2Sock;
struct Tun2Sock_s
{
    /***
     * stdlib realloc like
     */
    void* (*realloc)(void* ptr, size_t size);

    /***
     * The number of (milli)seconds elapsed from a monotonic clock
     * The unit of time this function returns does not matter
     * As long as the unit is the same used in the timeouts, all will be fine
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
     * The timeout for a connection
     * After this much time of inaction, the connection/NAT will be released and reused
     * The unit should be the same returned by the time() function
     */
    uint32_t timeout;

    /***
     * The bits of maximum connections this lib can handle simutaneously
     * A value of N means (2 ** N) number of connections
     */
    int max_connections_bits;

    //TODO: Add more options to fine tune

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
 * Get library version
 * @param major     The major version number output
 * @param minor     The minor version number output
 */
void tun2sock_get_version(int* major, int* minor);

/***
 * Input a packet
 * This function should be called when a IP(v4/v6) packet is received from the TUN
 * This function will decide if the packet should be dropped or modified and send back to the TUN
 * When a NAT is found/created, this function will modify the headers of the packet
 * When an error occurred, this function may rewrite a error response into the buffer
 * The buffer containing the packet should be at lest large enough for an ICMP destination unreachable message
 * Which is:
 *      IPv4:   20 + 8 + Original IPv4 header length + 8 bytes long
 *      IPv6:   40 + 8 + Original IPv6 header length + 8 bytes long
 * @param t2s       The Tun2Sock struct
 * @param pkt       The packet (Need to be a valid IP packet and mutable and big enough for error message)
 * @return          >0 The total length of the modified packet to be send back to the TUN
 *                  <0 Error number, and the packet shoud be dropped
 */
int tun2sock_input(Tun2Sock* t2s, uint8_t* pkt);

/***
 * Get the original destination port using the NAT address
 * !NOTE: The port returned is in network order
 * @param t2s       The Tun2Sock struct
 * @param addr      The IP address
 * @param port      The port
 * @return          >0 The original port
 *                  <0 Error number
 */
int_fast32_t tun2sock_get_original_port4(Tun2Sock* t2s, uint8_t addr[4], uint16_t port);
int_fast32_t tun2sock_get_original_port6(Tun2Sock* t2s, uint8_t addr[16], uint16_t port);

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
int_fast32_t tun2sock_add_nat4(Tun2Sock* t2s, uint8_t raddr[4], uint16_t rport, uint8_t laddr[4], uint16_t lport);
int_fast32_t tun2sock_add_nat6(Tun2Sock* t2s, uint8_t raddr[16], uint16_t rport, uint8_t laddr[16], uint16_t lport);

#endif /* _TUN2SOCK_H_ */
