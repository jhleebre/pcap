/*
 * pcapReader
 *
 * Jihyung Lee
 * September 9, 2015 
 *
 * Read and process each packet in a pcap file.
 */

/******************************************************************************
 * Header files
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/in6.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <signal.h>

#include "config.h"
#include "pcapReader.h"
#include "flowManager.h"

/******************************************************************************
 * Static variables
 */
static pcap_t * handle;            /* pcap file handler */
static uint64_t num_pkt            = 0; /* the number of packets */
static uint64_t num_byte           = 0; /* the total bytes of packets */
static uint64_t num_ipv4_pkt       = 0; /* the number of IPv4 packets */
static uint64_t num_ipv6_pkt       = 0; /* the number of IPv6 packets */
static uint64_t num_tcp_pkt        = 0; /* the number of TCP packets */
static uint64_t num_udp_pkt        = 0; /* the number of UDP packets */
static uint64_t num_icmp_pkt       = 0; /* the number of ICMP packets */
static uint64_t num_oth_pkt        = 0; /* the number of other packets */
static uint64_t num_ipv4_byte      = 0; /* the total bytes of IPv4 packets */
static uint64_t num_ipv6_byte      = 0; /* the total bytes of IPv6 packets */
static uint64_t num_tcp_byte       = 0; /* the total bytes of TCP packets */
static uint64_t num_udp_byte       = 0; /* the total bytes of UDP packets */
static uint64_t num_icmp_byte      = 0; /* the total bytes of ICMP packets */
static uint64_t num_oth_byte       = 0; /* the total bytes of other packets */
static uint64_t num_syn_pkt        = 0; /* the number of TCP SYN packets */
static uint64_t num_synack_pkt     = 0; /* the number of TCP SYN-ACK packets */
static uint64_t num_fin_pkt        = 0; /* the number of TCP FIN packets */
static uint64_t num_rst_pkt        = 0; /* the number of TCP RST packets */
static uint64_t num_flow           = 0; /* the total number of flows */
static uint64_t sportPktCnt[65536] = {0}; /* source port packet counter */
static uint64_t dportPktCnt[65536] = {0}; /* destination port packet counter */
static uint64_t sportByteCnt[65536]= {0}; /* source port byte counter */
static uint64_t dportByteCnt[65536]= {0}; /* destination port byte counter */
static flowTable_t flowTable;		  /* the flow table */
static struct timeval ts[2] = {{0, 0}, {0, 0}};	/* arrival times of the first
						   and the last packets */
/* an array to recode SYN arriving time */
static struct timeval syn_arr_ts[2] = {{0, 0}, {0, 0}}; 

/******************************************************************************
 * Function prototypes
 */
static inline void print_usage   (char *app_name);
static        void signal_handler(int signum);
static inline int  process_packet(struct pcap_pkthdr *hdr, const u_char *pkt);
static inline void print_packet  (struct pcap_pkthdr *hdr, const u_char *pkt);
static inline void pkt_count     (const u_char *pkt, uint32_t len);
static inline void check_flows   (void);

/******************************************************************************
 * main
 * - Open a pcap file and read packets in it to process each of them.
 */
int
main(int argc, char *argv[])
{
  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr hdr;
  const u_char *pkt;

  /* check the input arguments */
  if (argc != 2) {
    print_usage(argv[0]);
    return 0;
  }

  /* set interrupt handler */
  if (signal(SIGINT, signal_handler) == SIG_ERR) {
    perror("signal");
    return 0;
  }

  /* open the pcap file */
  handle = pcap_open_offline(argv[1], errbuf);
  if (handle == NULL) {
    fprintf(stderr, "pcap_open_offline: %s", errbuf);
    return 0;
  }

  /* create flow table */
  flowTable = flowTable_create();
  if (flowTable == NULL) {
    fprintf(stderr, "flowTable_create failure\n");
    pcap_close(handle);
    return 0;
  }

  printf("pcap file    : %s\n", argv[1]);

  /* read packets from the pcap file */
  while ((pkt = pcap_next(handle, &hdr))) {
    if (hdr.ts.tv_sec == 0)
      break;
    if (ts[0].tv_sec == 0)
      ts[0] = hdr.ts;
    ts[1] = hdr.ts;

    if (process_packet(&hdr, pkt) == -1) {
      fprintf(stderr, "process_packet failure\n");
      break;
    }
  }

  /* close the pcap file */
  pcap_close(handle);
  handle = NULL;

  printf("total packets: %"PRIu64"\n", num_pkt);
  printf("total bytes  : %"PRIu64"\n", num_byte);
  printf("IPv4  packets: %"PRIu64"\n", num_ipv4_pkt);
  printf("IPv4  bytes  : %"PRIu64"\n", num_ipv4_byte);
  printf("IPv6  packets: %"PRIu64"\n", num_ipv6_pkt);
  printf("IPv6  bytes  : %"PRIu64"\n", num_ipv6_byte);
  printf("TCP   packets: %"PRIu64"\n", num_tcp_pkt);
  printf("TCP   bytes  : %"PRIu64"\n", num_tcp_byte);
  printf("- SYN packets: %"PRIu64"\n", num_syn_pkt);
  printf("- S-A packets: %"PRIu64"\n", num_synack_pkt);
  printf("- FIN packets: %"PRIu64"\n", num_fin_pkt);
  printf("- RST packets: %"PRIu64"\n", num_rst_pkt);
  printf("UDP   packets: %"PRIu64"\n", num_udp_pkt);
  printf("UDP   bytes  : %"PRIu64"\n", num_udp_byte);
  printf("ICMP  packets: %"PRIu64"\n", num_icmp_pkt);
  printf("ICMP  bytes  : %"PRIu64"\n", num_icmp_byte);
  printf("other packets: %"PRIu64"\n", num_oth_pkt);
  printf("other bytes  : %"PRIu64"\n", num_oth_byte);
  //printf("## a flow is a 5-tuple fair regardless of the direction in this program\n");
  printf("total flows  : %"PRIu64"\n", num_flow);

  /* check concurrent flows */
  check_flows();

  double syn2syn = ((syn_arr_ts[1].tv_sec + syn_arr_ts[1].tv_usec*1e-6) -
		    (syn_arr_ts[0].tv_sec + syn_arr_ts[0].tv_usec*1e-6));
  printf("Avg SYN IAT  : %f sec\n", syn2syn / num_syn_pkt);

  /* destroy flow table */
  flowTable_destroy(flowTable);

  return 0;
}

/******************************************************************************
 * print_usage
 * - Print out usage command.
 */
static inline void
print_usage(char *app_name)
{
  fprintf(stderr, "Usage: %s [PCAP_FILE]\n", app_name);
}

/******************************************************************************
 * signal_handler
 * - An interrupt handler that closes the pcap file and terminates the process.
 */
static void
signal_handler(int signum)
{
  if (signum != SIGINT)
    exit(1);

  if (handle != NULL)
    pcap_close(handle);

  flowTable_destroy(flowTable);

  exit(0);
}

/******************************************************************************
 * process_packet
 * - Process a packet
 *   * Print packet data
 *   * TCP flow tracking
 *   * Counting the total number of packets/bytes/flows 
 *   * Counting the number of concurrent flows
 *   * Check the flow sizes, durations, and inter-arrival time
 *   * etc.
 */
static inline int
process_packet(struct pcap_pkthdr *hdr, const u_char *pkt)
{
  flow_t f;
  uint64_t prev_num_tcp_pkt = num_tcp_pkt;

  //print_packet(hdr, pkt);

  pkt_count(pkt, hdr->len);

  if (prev_num_tcp_pkt == num_tcp_pkt)
    return 0;

  /* TCP flow tracking 
   * - In this program, a flow means a 5-tuple fair.
   */
  struct tcphdr *tcp_hdr = get_tcp_hdr(pkt);
  if (tcp_hdr->syn == 1 && tcp_hdr->ack == 0) {
    if (num_syn_pkt == 1)
      syn_arr_ts[0] = hdr->ts;
    syn_arr_ts[1] = hdr->ts;
  }

  f = flowTable_lookup(flowTable, pkt);
  if (f == NULL) {
    f = flowTable_create_flow(flowTable, hdr, pkt);
    if (f == NULL) {
      fprintf(stderr, "flowTable_create_flow failure\n");
      return -1;
    }
    num_flow++;
  }
  else {
    flowTable_update_flow(flowTable, f, hdr, pkt);
  }
  
  return 0;
}

/******************************************************************************
 * pkt_count
 * - Analyze packet header and update relevent counters
 */
static inline void
pkt_count(const u_char *pkt, uint32_t len)
{
  struct ethhdr *ether_hdr = (struct ethhdr *)pkt;
  uint16_t ether_type = ntohs(ether_hdr->h_proto);
  uint8_t  protocol;

  /* update packet counter */
  num_pkt++;
  num_byte += len;
  
  /* analyze protocol */
  if (ether_type == ETH_P_IP) {
    struct iphdr *ipv4_hdr = get_ipv4_hdr(pkt);
    num_ipv4_pkt++;
    num_ipv4_byte += len;
    protocol = ipv4_hdr->protocol;
  }
  else if (ether_type == ETH_P_IPV6) {
    struct ipv6hdr *ipv6_hdr = get_ipv6_hdr(pkt);
    num_ipv6_pkt++;
    num_ipv6_byte += len;
    protocol = ipv6_hdr->nexthdr;
  }
  else {
    num_oth_pkt++;
    num_oth_byte += len; 
    return;
  }
  
  /* update layer 4 counter */
  if (protocol == IPPROTO_TCP) {
    struct tcphdr *tcp_hdr = get_tcp_hdr(pkt);
    sportPktCnt[ntohs(tcp_hdr->source)]++;
    dportPktCnt[ntohs(tcp_hdr->dest)]++;
    sportByteCnt[ntohs(tcp_hdr->source)] += len;
    dportByteCnt[ntohs(tcp_hdr->dest)] += len;
    num_tcp_pkt++;
    num_tcp_byte += len;
    
    if (tcp_hdr->syn)
      if (tcp_hdr->ack)
	num_synack_pkt++;
      else
	num_syn_pkt++;
    else if (tcp_hdr->fin)
      num_fin_pkt++;
    else if (tcp_hdr->rst)
      num_rst_pkt++;
  }
  else if (protocol == IPPROTO_UDP) {
    struct udphdr *udp_hdr = get_udp_hdr(pkt);
    sportPktCnt[ntohs(udp_hdr->source)]++;
    dportPktCnt[ntohs(udp_hdr->dest)]++;
    sportByteCnt[ntohs(udp_hdr->source)] += len;
    dportByteCnt[ntohs(udp_hdr->dest)] += len;
    num_udp_pkt++;
    num_udp_byte += len;
  }
  else if (protocol == IPPROTO_ICMP) {
    num_icmp_pkt++;
    num_icmp_byte += len;
  }
  else {
    // Do I need to distinguish two other cases at L3 and L4?
    num_oth_pkt++;
    num_oth_byte += len; 
  }
}

/******************************************************************************
 * print_packet
 * - Print out packet data.
 *   * pcap packet header
 *   * Ethernet frame header
 *   * IP header
 *   * TCP/UDP header
 *   * etc.
 */
static inline void
print_packet(struct pcap_pkthdr *hdr, const u_char *pkt)
{
  struct ethhdr *ether_hdr = (struct ethhdr *)pkt;
  uint16_t ether_type = ntohs(ether_hdr->h_proto);
  uint8_t  protocol;

  /* print pcap packet header */
  printf("--------------------------------------------------------\n");
  //printf("Arrival time : %lu.%lu\n", hdr->ts.tv_sec, hdr->ts.tv_usec);
  printf("Arrival time : %s", ctime(&hdr->ts.tv_sec));
  printf("Packet length: %u (%u) bytes\n", hdr->caplen, hdr->len);
  
  /* print MAC addresses */
  printf("Src MAC Addr : %02x:%02x:%02x:%02x:%02x:%02x\n",
	 ether_hdr->h_source[0], ether_hdr->h_source[1],
	 ether_hdr->h_source[2], ether_hdr->h_source[3],
	 ether_hdr->h_source[4], ether_hdr->h_source[5]);
  printf("Dst MAC Addr : %02x:%02x:%02x:%02x:%02x:%02x\n", 
	 ether_hdr->h_dest[0], ether_hdr->h_dest[1],
	 ether_hdr->h_dest[2], ether_hdr->h_dest[2], 
	 ether_hdr->h_dest[4], ether_hdr->h_dest[3]);

  /* print IP addresses if the packet is an IPv4 or IPv6 packet */
  if (ether_type == ETH_P_IP) {
    printf("Ether type   : IPv4\n");
    struct iphdr *ipv4_hdr = get_ipv4_hdr(pkt);
    printf("Src IPv4 Addr: %s\n",
	   inet_ntoa(*(struct in_addr *)&(ipv4_hdr->saddr)));
    printf("Dst IPv4 Addr: %s\n",
	   inet_ntoa(*(struct in_addr *)&(ipv4_hdr->daddr)));
    protocol = ipv4_hdr->protocol;
  }
  else if (ether_type == ETH_P_IPV6) {
    printf("Ether type   : IPv6\n");
    struct ipv6hdr *ipv6_hdr = get_ipv6_hdr(pkt);
    int i;
    unsigned char *p = (unsigned char *)&ipv6_hdr->saddr;
    printf("Src IPv6 Addr: %02x", *p++);
    for (i = 1; i < 16; i++)
      printf(":%02x", *p++);
    printf("\n");
    printf("Dst IPv6 Addr: %02x", *p++);
    for (i = 1; i < 16; i++)
      printf(":%02x", *p++);
    printf("\n");
    protocol = ipv6_hdr->nexthdr;
  }
  else if (ether_type == ETH_P_8021Q) {
    printf("Ether type   : 802.1Q VLAN\n");
    return;
  }
  else if (ether_type == ETH_P_ARP) {
    printf("Ether type   : ARP\n");
    return;
  }
  else {
    printf("Ether type   : %hu\n", ether_type);
    return;
  }

  /* print port numbers if the packet is a TCP or UDP packet */
  if (protocol == IPPROTO_TCP) {
    printf("Protocol     : TCP\n");
    struct tcphdr *tcp_hdr = get_tcp_hdr(pkt);
    printf("Src port     : %hu\n", ntohs(tcp_hdr->source));
    printf("Dst port     : %hu\n", ntohs(tcp_hdr->dest));
    printf("Flags        : %s%s%s%s%s%s%s%s\n",
	   tcp_hdr->fin ? "FIN" : "", tcp_hdr->syn ? "SYN" : "",
	   tcp_hdr->rst ? "RST" : "", tcp_hdr->psh ? "PSH" : "",
	   tcp_hdr->ack ? "ACK" : "", tcp_hdr->urg ? "URG" : "",
	   tcp_hdr->ece ? "ECE" : "", tcp_hdr->cwr ? "CWR" : "");
  }
  else if (protocol == IPPROTO_UDP) {
    printf("Protocol     : UDP\n");
    struct udphdr *udp_hdr = get_udp_hdr(pkt);
    printf("Src port     : %hu\n", ntohs(udp_hdr->source));
    printf("Dst port     : %hu\n", ntohs(udp_hdr->dest));
  }
  else if (protocol == IPPROTO_ICMP) {
    printf("Protocol     : ICMP\n");
    return;
  }
  else {
    printf("Protocol     : %u\n", (unsigned)protocol);
    return;
  }
}

/******************************************************************************
 * check_flows
 * - Check the flows in the flowTable and measure the flow statistics such as
 *   * the number of packets in each flow
 *   * the size and duration of each flow
 *   * the number of concurrent flows
 *   * etc.
 */
static inline void
check_flows(void)
{
  int i;
  flowQueue *fq;
  flow_t f;
  uint64_t first = (ts[0].tv_sec*1000000 + ts[0].tv_usec)/SAMPLING_PERIOD;
  uint64_t last  = (ts[1].tv_sec*1000000 + ts[1].tv_usec)/SAMPLING_PERIOD + 1;
  uint64_t conc_flow[last - first];
  uint64_t j;
  uint64_t sum[3] = {0, 0, 0};

  memset(conc_flow, 0, (last - first) * sizeof(uint64_t));

  for (i = 0; i < FLOW_TABLE_SIZE; i++) {
    fq = &flowTable->table[i];
    TAILQ_FOREACH(f, fq, node) {
      uint64_t start = f->ts[0].tv_sec*1000000 + f->ts[0].tv_usec;
      uint64_t end = f->ts[1].tv_sec*1000000 + f->ts[1].tv_usec;
      /*
      printf("flow size: %"PRIu64" bytes\n", f->num_byte);
      printf("flow pkts: %"PRIu64" pkts\n", f->num_pkt);
      printf("duration : %"PRIu64" us\n", end - start);
      */
      sum[0] += f->num_byte;
      sum[1] += f->num_pkt;
      sum[2] += end - start;

      start /= SAMPLING_PERIOD;
      end   /= SAMPLING_PERIOD;

      for (j = start - first; j <= end - first; j++) {
	conc_flow[j]++;
      }
    }
  }

  for (j = 0; j < last - first; j++) {
    //printf("%"PRIu64"\t%"PRIu64"\n", first + j, conc_flow[j]);
  }

  printf("Avg flow size: %"PRIu64" bytes\n", sum[0]/num_flow);
  printf("Avg flow pkts: %"PRIu64" pkts\n", sum[1]/num_flow);
  printf("Avg duration : %f sec\n", (double)sum[2]/(double)num_flow*1e-6);
}

/******************************************************************************
 * get_ipv4_hdr
 * - Return the address of IPv4 header in the raw Ethernet frame bytestream.
 */
inline struct iphdr *
get_ipv4_hdr(const u_char *pkt)
{
  /*
  if (ntohs(((struct ethhdr *)pkt)->h_proto) == ETH_P_8021Q)
    return (struct iphdr *)(pkt + sizeof(struct ethhdr) +
			    sizeof(struct vlan_hdr));
  else
  */
  return (struct iphdr *)(pkt + sizeof(struct ethhdr));
}

/******************************************************************************
 * get_ipv6_hdr
 * - Return the address of IPv6 header in the raw Ethernet frame bytestream.
 */
inline struct ipv6hdr *
get_ipv6_hdr(const u_char *pkt)
{
  /*
  if (ntohs(((struct ethhdr *)pkt)->h_proto) == ETH_P_8021Q)
    return (struct ipv6hdr *)(pkt + sizeof(struct ethhdr) +
			    sizeof(struct vlan_hdr));
  else
  */
  return (struct ipv6hdr *)(pkt + sizeof(struct ethhdr));
}

/******************************************************************************
 * get_tcp_hdr
 * - Return the address of TCP header in the raw Ethernet frame bytestream.
 */
inline struct tcphdr *
get_tcp_hdr(const u_char *pkt)
{
  struct ethhdr *ether_hdr = (struct ethhdr *)pkt;
  uint16_t ether_type = ntohs(ether_hdr->h_proto);
  
  if (ether_type == ETH_P_IP) {
    struct iphdr *ip_hdr = get_ipv4_hdr(pkt);
    return (struct tcphdr *)(pkt + sizeof(struct ethhdr)
			     + (ip_hdr->ihl << 2));
  }
  else if (ether_type == ETH_P_IPV6) {
    return (struct tcphdr *)(pkt + sizeof(struct ethhdr)
			     + sizeof(struct ipv6hdr));
  }
  else {
    return NULL;
  }
}

/******************************************************************************
 * get_udp_hdr
 * - Return the address of UDP header in the raw Ethernet frame bytestream.
 */
inline struct udphdr *
get_udp_hdr(const u_char *pkt)
{
  struct ethhdr *ether_hdr = (struct ethhdr *)pkt;
  uint16_t ether_type = ntohs(ether_hdr->h_proto);

  if (ether_type == ETH_P_IP) {
    struct iphdr *ip_hdr = get_ipv4_hdr(pkt);
    return (struct udphdr *)(pkt + sizeof(struct ethhdr)
			     + (ip_hdr->ihl << 2));
  }
  else if (ether_type == ETH_P_IPV6) {
    return (struct udphdr *)(pkt + sizeof(struct ethhdr)
			     + sizeof(struct ipv6hdr));
  }
  else {
    return NULL;
  }
}

