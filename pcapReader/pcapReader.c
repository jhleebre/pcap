#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
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
#include <signal.h>

pcap_t *handle;

static void
signal_handler(int signum)
{
  if (signum != SIGINT)
    exit(1);

  pcap_close(handle);
  exit(0);
}

static inline void
print_usage(char *app_name)
{
  fprintf(stderr, "Usage: %s [PCAP_FILE]\n", app_name);
}

static inline struct iphdr *
get_ipv4_hdr(const u_char *pkt)
{
  /*
  if (unlikely(ntohs(((struct ethhdr *)pkt)->h_proto) == ETH_P_8021Q))
    return (struct iphdr *)(pkt + sizeof(struct ethhdr) +
			    sizeof(struct vlan_hdr));
  else
  */
    return (struct iphdr *)(pkt + sizeof(struct ethhdr));
}

static inline struct ipv6hdr *
get_ipv6_hdr(const u_char *pkt)
{
  /*
  if (unlikely(ntohs(((struct ethhdr *)pkt)->h_proto) == ETH_P_8021Q))
    return (struct ipv6hdr *)(pkt + sizeof(struct ethhdr) +
			    sizeof(struct vlan_hdr));
  else
  */
    return (struct ipv6hdr *)(pkt + sizeof(struct ethhdr));
}

static inline struct tcphdr *
get_tcp_hdr(const u_char *pkt)
{
  struct ethhdr *ether_hdr = (struct ethhdr *)pkt;
  uint16_t ether_type = ntohs(ether_hdr->h_proto);

  if (ether_type == ETH_P_IP) {
    struct iphdr *ip_hdr = get_ipv4_hdr(pkt);
    return (struct tcphdr *)(pkt + sizeof(struct ethhdr) + (ip_hdr->ihl << 2));
  }
  else if (ether_type == ETH_P_IPV6) {
    return (struct tcphdr *)(pkt + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
  }
  else {
    return NULL;
  }
}

static inline struct udphdr *
get_udp_hdr(const u_char *pkt)
{
  struct ethhdr *ether_hdr = (struct ethhdr *)pkt;
  uint16_t ether_type = ntohs(ether_hdr->h_proto);

  if (ether_type == ETH_P_IP) {
    struct iphdr *ip_hdr = get_ipv4_hdr(pkt);
    return (struct udphdr *)(pkt + sizeof(struct ethhdr) + (ip_hdr->ihl << 2));
  }
  else if (ether_type == ETH_P_IPV6) {
    return (struct udphdr *)(pkt + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
  }
  else {
    return NULL;
  }
}

static inline void
process_packet(const u_char *pkt, struct pcap_pkthdr *hdr)
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
    printf("Src IPv4 Addr: %s\n", inet_ntoa(*(struct in_addr *)&(ipv4_hdr->saddr)));
    printf("Dst IPv4 Addr: %s\n", inet_ntoa(*(struct in_addr *)&(ipv4_hdr->daddr)));
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

  /* read packets from the pcap file */
  while ((pkt = pcap_next(handle, &hdr))) {
    if (hdr.ts.tv_sec == 0)
      break;

    process_packet(pkt, &hdr);
  }

  /* close the pcap file */
  pcap_close(handle);

  return 0;
}
