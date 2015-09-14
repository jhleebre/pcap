/******************************************************************************
 * Header files
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/in6.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <assert.h>
#include <pcap.h>

#include "config.h"
#include "pcapReader.h"
#include "flowManager.h"

/******************************************************************************
 * Function prototypes
 */
static inline uint32_t flowTable_hash(const u_char *pkt);
static inline bool     flowTable_match(flow_t f, const u_char *pkt);

/******************************************************************************
 * flowTable_create
 */
inline flowTable_t
flowTable_create(void)
{
  flowTable_t ft;
  int i;

  ft = (flowTable_t)malloc(sizeof(struct flowTable));
  if (ft == NULL) {
    perror("malloc");
    return NULL;
  }

  for (i = 0; i < FLOW_TABLE_SIZE; i++)
    TAILQ_INIT(&ft->table[i]);

  return ft;
}

/******************************************************************************
 * flowTable_destroy
 */
inline void
flowTable_destroy(flowTable_t ft)
{
  int i;
  flowQueue *fq;
  flow_t f;

  for (i = 0; i < FLOW_TABLE_SIZE; i++) {
    fq = &ft->table[i];
    while ((f = TAILQ_FIRST(fq))) {
      TAILQ_REMOVE(fq, f, node);
      free(f);
    }
  }
  
  free(ft);
}

/******************************************************************************
 * flowTable_lookup
 */
inline flow_t
flowTable_lookup(flowTable_t ft, const u_char *pkt)
{
  flowQueue *fq;
  flow_t f;
  uint32_t hash = flowTable_hash(pkt);

  fq = &ft->table[hash];
  TAILQ_FOREACH(f, fq, node) {
    if (flowTable_match(f, pkt)) {
      return f;
    }
  }

  return NULL;
}

/******************************************************************************
 * flowTable_lookup
 */
#define UPDATE_HASH(hash, key) {		\
    (hash) += (key);				\
    (hash) += ((hash) << 10);			\
    (hash) ^= ((hash) >> 6);			\
  }
static inline uint32_t
flowTable_hash(const u_char *pkt)
{
  struct ethhdr *ether_hdr = (struct ethhdr *)pkt;
  uint16_t ether_type = ntohs(ether_hdr->h_proto);
  uint32_t addr[2] = {0, 0};
  //
  struct tcphdr *tcp_hdr = get_tcp_hdr(pkt);
  uint16_t port[2] = {(uint16_t)tcp_hdr->source, (uint16_t)tcp_hdr->dest};
  //
  uint32_t hash[2] = {0, 0};
  int i, j;
  char *key;

  if (ether_type == ETH_P_IP) {
    struct iphdr *ipv4_hdr = get_ipv4_hdr(pkt);
    addr[0] = (uint32_t)ipv4_hdr->saddr;
    addr[1] = (uint32_t)ipv4_hdr->daddr;
  }
  else if (ether_type == ETH_P_IPV6) {
    struct ipv6hdr *ipv6_hdr = get_ipv6_hdr(pkt);
    uint32_t *sp = (uint32_t *)&ipv6_hdr->saddr;
    uint32_t *dp = (uint32_t *)&ipv6_hdr->daddr;;
    for (i = 0; i < 4; i++) {
      addr[0] += *sp++;
      addr[1] += *dp++;
    }
  }
  else {
    assert(0); /* Do I need more graceful error handling? */
  }

  for (i = 0; i < 2; i++) {
    key = (char *)&addr[i];
    for (j = 0; j < 4; j++)
      UPDATE_HASH(hash[i], key[j]);
    //
    key = (char *)&port[i];
    for (j = 0; j < 2; j++)
      UPDATE_HASH(hash[i], key[j]);
    //
  }

  hash[0] += hash[1];
  hash[0] += (hash[0] << 3);
  hash[0] ^= (hash[0] >> 11);
  hash[0] += (hash[0] << 15);

  return hash[0] % FLOW_TABLE_SIZE;
}

/******************************************************************************
 * flowTable_match
 */
static inline bool
flowTable_match(flow_t f, const u_char *pkt)
{
  struct ethhdr *ether_hdr = (struct ethhdr *)pkt;
  uint16_t ether_type = ntohs(ether_hdr->h_proto);

  if (ether_type != f->ether_type)
    return false;
  //
    struct tcphdr *tcp_hdr = get_tcp_hdr(pkt);
  //
  if (ether_type == ETH_P_IP) {
    struct iphdr *ipv4_hdr = get_ipv4_hdr(pkt);
    return ((f->saddr.s6_addr32[0] == ipv4_hdr->saddr &&
	     f->daddr.s6_addr32[0] == ipv4_hdr->daddr &&
	     f->sport              == tcp_hdr->source &&
	     f->dport              == tcp_hdr->dest) ||
	    (f->saddr.s6_addr32[0] == ipv4_hdr->daddr &&
	     f->daddr.s6_addr32[0] == ipv4_hdr->saddr &&
	     f->sport              == tcp_hdr->dest &&
	     f->dport              == tcp_hdr->source));
  }
  else if (ether_type == ETH_P_IPV6) {
    struct ipv6hdr *ipv6_hdr = get_ipv6_hdr(pkt);
    return ((f->saddr.s6_addr32[0] == ipv6_hdr->saddr.s6_addr32[0] &&
	     f->saddr.s6_addr32[1] == ipv6_hdr->saddr.s6_addr32[1] &&
	     f->saddr.s6_addr32[2] == ipv6_hdr->saddr.s6_addr32[2] &&
	     f->saddr.s6_addr32[3] == ipv6_hdr->saddr.s6_addr32[3] &&
	     f->daddr.s6_addr32[0] == ipv6_hdr->daddr.s6_addr32[0] &&
	     f->daddr.s6_addr32[1] == ipv6_hdr->daddr.s6_addr32[1] &&
	     f->daddr.s6_addr32[2] == ipv6_hdr->daddr.s6_addr32[2] &&
	     f->daddr.s6_addr32[3] == ipv6_hdr->daddr.s6_addr32[3] &&
	     f->sport == tcp_hdr->source && f->dport == tcp_hdr->dest) ||
	    (f->saddr.s6_addr32[0] == ipv6_hdr->daddr.s6_addr32[0] &&
	     f->saddr.s6_addr32[1] == ipv6_hdr->daddr.s6_addr32[1] &&
	     f->saddr.s6_addr32[2] == ipv6_hdr->daddr.s6_addr32[2] &&
	     f->saddr.s6_addr32[3] == ipv6_hdr->daddr.s6_addr32[3] &&
	     f->daddr.s6_addr32[0] == ipv6_hdr->saddr.s6_addr32[0] &&
	     f->daddr.s6_addr32[1] == ipv6_hdr->saddr.s6_addr32[1] &&
	     f->daddr.s6_addr32[2] == ipv6_hdr->saddr.s6_addr32[2] &&
	     f->daddr.s6_addr32[3] == ipv6_hdr->saddr.s6_addr32[3] &&
	     f->sport == tcp_hdr->dest && f->dport == tcp_hdr->source));
  }
  else {
    assert(0); /* Do I need more graceful error handling? */
  }

  return false;
}

/******************************************************************************
 * flowTable_create_flow
 */
inline flow_t 
flowTable_create_flow(flowTable_t ft,
		      struct pcap_pkthdr *hdr, const u_char *pkt)
{
  flow_t f;
  uint32_t hash = flowTable_hash(pkt);
  flowQueue *fq = &ft->table[hash];
  struct ethhdr *ether_hdr = (struct ethhdr *)pkt;
  //
  struct tcphdr *tcp_hdr = get_tcp_hdr(pkt);
  //

  f = (flow_t)malloc(sizeof(struct flow));
  if (f == NULL) {
    perror("malloc");
    return NULL;
  }
  
  f->ether_type = ntohs(ether_hdr->h_proto);

  if (f->ether_type == ETH_P_IP) {
    struct iphdr *ipv4_hdr = get_ipv4_hdr(pkt);
    f->saddr.s6_addr32[0] = ipv4_hdr->saddr;
    f->daddr.s6_addr32[0] = ipv4_hdr->daddr;
  }
  else if (f->ether_type == ETH_P_IPV6) {
    struct ipv6hdr *ipv6_hdr = get_ipv6_hdr(pkt);
    f->saddr = ipv6_hdr->saddr;
    f->daddr = ipv6_hdr->daddr;
  }
  else {
    assert(0);  /* Do I need more graceful error handling? */
  }
  //
    f->sport = tcp_hdr->source;
    f->dport = tcp_hdr->dest;
  //
  f->ts[FIRST] = hdr->ts;
  f->ts[LAST]  = hdr->ts;

  /*
  if (tcphdr->syn)
    f->state = tcphdr->ack ? SYNACK : SYN;
  else if (tcphdr->rst)
    f->state = RST;
  else
    f->state = tcphdr->fin ? UNCLEAR_FIN : UNCLEAR;
  */
  f->num_byte = hdr->len;
  f->num_pkt  = 1;

  TAILQ_INSERT_HEAD(fq, f, node);
  
  return f;
}

/******************************************************************************
 * flowTable_update_flow
 */
inline void
flowTable_update_flow(flowTable_t ft, flow_t f,
		      struct pcap_pkthdr *hdr, const u_char *pkt)
{
  uint32_t hash = flowTable_hash(pkt);
  flowQueue *fq = &ft->table[hash];
  //struct tcphdr *tcp_hdr = get_tcp_hdr(pkt);

  TAILQ_REMOVE(fq, f, node);

  f->ts[LAST] = hdr->ts;
  f->num_byte += hdr->len;
  f->num_pkt++;

  TAILQ_INSERT_HEAD(fq, f, node);
}
