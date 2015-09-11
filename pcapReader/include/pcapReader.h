#ifndef __PCAPREADER_H__
#define __PCAPREADER_H__

/******************************************************************************
 * Header files
 */
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>

/******************************************************************************
 * Function Prototypes
 */
inline struct iphdr   * get_ipv4_hdr(const u_char *pkt);
inline struct ipv6hdr * get_ipv6_hdr(const u_char *pkt);
inline struct tcphdr  * get_tcp_hdr (const u_char *pkt);
inline struct udphdr  * get_udp_hdr (const u_char *pkt);

#endif
