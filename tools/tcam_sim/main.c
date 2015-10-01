/* TCAM size simulation
 *
 * Jihyung Lee
 * Oct 1, 2015
 */
/******************************************************************************
 * Header files
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
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
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <signal.h>
#include <assert.h>
/******************************************************************************
 * Configurations
 */
#define NUM_DISK 30		      /* the number of disks */
#define TCAM_LOOKUP_TABLE_SIZE 100000 /* TCAM lookup table size */
/******************************************************************************
 * Abstract data types
 */
struct tcam_entry {
  struct in6_addr saddr;	/* source IP address */
  struct in6_addr daddr;	/* destination IP address */
  __u16 sport;			/* source prot */
  __u16 dport;			/* destination port */
  uint64_t ts;			/* us timestamp */
  uint16_t ether_type;		/* IPv4 or IPv6 */
  uint8_t protocol;  		/* TCP or UDP */
  uint32_t idx;			/* TCAM lookup table index */
  TAILQ_ENTRY(tcam_entry) node;	/* lookup table entry */
  TAILQ_ENTRY(tcam_entry) link; /* FIFO linked list for timeout check */
};
typedef TAILQ_HEAD(table, tcam_entry) TEQ; /* TCAM entry queue */
/******************************************************************************
 * Global variables
 */
TEQ tcamtable[TCAM_LOOKUP_TABLE_SIZE]; /* TCAM entry lookup table */
TEQ tcamfifo;			       /* TCAM entry FIFO queue */
int ttl;			       /* TCAM entry time to live in us*/
uint64_t num_tcam_entry = 0;	       /* the number of TCAM entries */
uint64_t max_tcam_entry = 0;	       /* the maximum number of TCAM entries */
uint64_t num_query = 0;		       /* the number of control messages */
uint64_t prev_num_query = 0;	       /* the previous number of CMs */
time_t prev_t = 0;		       /* the previous printing time */
char *path[NUM_DISK] = {
  "/mnt/work_01/", "/mnt/work_02/", "/mnt/work_03/", "/mnt/work_04/",
  "/mnt/work_05/", "/mnt/work_06/", "/mnt/work_07/", "/mnt/work_08/",
  "/mnt/work_09/", "/mnt/work_10/", "/mnt/work_11/", "/mnt/work_12/",
  "/mnt/work_13/", "/mnt/work_14/", "/mnt/work_15/", "/mnt/work_16/",
  "/mnt/work_17/", "/mnt/work_18/", "/mnt/work_19/", "/mnt/work_20/",
  "/mnt/work_21/", "/mnt/work_22/", "/mnt/work_23/", "/mnt/work_24/",
  "/mnt/work_25/", "/mnt/work_26/", "/mnt/work_27/", "/mnt/work_28/",
  "/mnt/work_29/", "/mnt/work_30/"}; /* PCAP file paths */
pcap_t *handle[NUM_DISK] = {NULL};   /* PCAP file handlers */
/******************************************************************************
 * Function: get_ipv4_hdr
 * - Return the IPv4 header of given Ethernet frame.
 */
inline struct iphdr *
get_ipv4_hdr(const u_char *pkt)
{
  return (struct iphdr *)(pkt + sizeof(struct ethhdr));
}
/******************************************************************************
 * Function: get_ipv6_hdr
 * - Return the IPv6 header of given Ethernet frame.
 */
inline struct ipv6hdr *
get_ipv6_hdr(const u_char *pkt)
{
  return (struct ipv6hdr *)(pkt + sizeof(struct ethhdr));
}
/******************************************************************************
 * Function: get_tcp_hdr
 * - Return the TCP header of given Ethernet frame.
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
 * Function: get_udp_hdr
 * - Return the UDP header of given Ethernet frame.
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
/******************************************************************************
 * Function: get_hash
 * - Return hash value of given Ethernet frame.
 * - Use IP addresses and port numbers for hashing.
 * - Return the same value for both cases of SRC->DEST and DEST->SRC.
 */
#define UPDATE_HASH(hash, key) {		\
    (hash) += (key);				\
    (hash) += ((hash) << 10);			\
    (hash) ^= ((hash) >> 6);			\
  }
static inline uint32_t
get_hash(const u_char *pkt)
{
  struct ethhdr *ether_hdr = (struct ethhdr *)pkt;
  uint16_t ether_type = ntohs(ether_hdr->h_proto);
  uint32_t addr[2] = {0, 0};
  struct udphdr *udp_hdr = get_udp_hdr(pkt);
  uint16_t port[2] = {(uint16_t)udp_hdr->source, (uint16_t)udp_hdr->dest};
  uint32_t hash[2] = {0, 0};
  int i, j;
  char *key;

  /* get the address values */
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

  /* calculate hash value */
  for (i = 0; i < 2; i++) {
    key = (char *)&addr[i];
    for (j = 0; j < 4; j++)
      UPDATE_HASH(hash[i], key[j]);
    key = (char *)&port[i];
    for (j = 0; j < 2; j++)
      UPDATE_HASH(hash[i], key[j]);
  }

  /* finalize hash value */
  hash[0] += hash[1];
  hash[0] += (hash[0] << 3);
  hash[0] ^= (hash[0] >> 11);
  hash[0] += (hash[0] << 15);

  return hash[0] % TCAM_LOOKUP_TABLE_SIZE;
}
/******************************************************************************
 * Function: tcamtable_match
 * - Check whether given Ethernet frame matches given TCAM entry.
 */
static inline bool
tcamtable_match(struct tcam_entry *te, const u_char *pkt)
{
  struct ethhdr *ether_hdr = (struct ethhdr *)pkt;
  uint16_t ether_type = ntohs(ether_hdr->h_proto);

  /* Ethernet type mismatch */
  if (ether_type != te->ether_type)
    return false;
  
  struct udphdr *udp_hdr = get_udp_hdr(pkt);
 
  /* IPv4 case */
  if (ether_type == ETH_P_IP) {
    struct iphdr *ipv4_hdr = get_ipv4_hdr(pkt);

    /* Transport layer protocol mismatch */
    if (te->protocol != ipv4_hdr->protocol)
      return false;

    return ((te->saddr.s6_addr32[0] == ipv4_hdr->saddr &&
             te->daddr.s6_addr32[0] == ipv4_hdr->daddr &&
             te->sport              == udp_hdr->source &&
             te->dport              == udp_hdr->dest) ||
            (te->saddr.s6_addr32[0] == ipv4_hdr->daddr &&
             te->daddr.s6_addr32[0] == ipv4_hdr->saddr &&
             te->sport              == udp_hdr->dest &&
             te->dport              == udp_hdr->source));
  }
  /* IPv6 case */
  else if (ether_type == ETH_P_IPV6) {
    struct ipv6hdr *ipv6_hdr = get_ipv6_hdr(pkt);

    /* Transport layer protocol mismatch */
    if (te->protocol != ipv6_hdr->nexthdr)
      return false;

    return ((te->saddr.s6_addr32[0] == ipv6_hdr->saddr.s6_addr32[0] &&
             te->saddr.s6_addr32[1] == ipv6_hdr->saddr.s6_addr32[1] &&
             te->saddr.s6_addr32[2] == ipv6_hdr->saddr.s6_addr32[2] &&
             te->saddr.s6_addr32[3] == ipv6_hdr->saddr.s6_addr32[3] &&
             te->daddr.s6_addr32[0] == ipv6_hdr->daddr.s6_addr32[0] &&
             te->daddr.s6_addr32[1] == ipv6_hdr->daddr.s6_addr32[1] &&
             te->daddr.s6_addr32[2] == ipv6_hdr->daddr.s6_addr32[2] &&
             te->daddr.s6_addr32[3] == ipv6_hdr->daddr.s6_addr32[3] &&
             te->sport == udp_hdr->source && te->dport == udp_hdr->dest) ||
            (te->saddr.s6_addr32[0] == ipv6_hdr->daddr.s6_addr32[0] &&
             te->saddr.s6_addr32[1] == ipv6_hdr->daddr.s6_addr32[1] &&
             te->saddr.s6_addr32[2] == ipv6_hdr->daddr.s6_addr32[2] &&
             te->saddr.s6_addr32[3] == ipv6_hdr->daddr.s6_addr32[3] &&
             te->daddr.s6_addr32[0] == ipv6_hdr->saddr.s6_addr32[0] &&
             te->daddr.s6_addr32[1] == ipv6_hdr->saddr.s6_addr32[1] &&
             te->daddr.s6_addr32[2] == ipv6_hdr->saddr.s6_addr32[2] &&
             te->daddr.s6_addr32[3] == ipv6_hdr->saddr.s6_addr32[3] &&
             te->sport == udp_hdr->dest && te->dport == udp_hdr->source));
  }
  else {
    assert(0); /* Do I need more graceful error handling? */
  }

  return false;
}
/******************************************************************************
 * Function: tcamtable_lookup
 * - Find a TCAM entry that matches with given Ethernet frame.
 */
static inline struct tcam_entry *
tcamtable_lookup(const u_char *pkt)
{
  struct tcam_entry *te;
  uint32_t idx = get_hash(pkt);

  /* traverse TCAM entries in the hash table bucket */
  TAILQ_FOREACH(te, &tcamtable[idx], node) {
    if (tcamtable_match(te, pkt))
      return te;
  }

  return NULL;
}
/******************************************************************************
 * Function: process_packet
 * - Run TCAM size simulation for each packet arrival.
 * - Ignore non IP packets and ICMP packets.
 */
static inline void
process_packet(struct pcap_pkthdr *hdr, const u_char *pkt) 
{
  struct ethhdr *ether_hdr = (struct ethhdr *)pkt;
  uint16_t ether_type = ntohs(ether_hdr->h_proto);
  uint8_t protocol;
  struct iphdr *ipv4_hdr;
  struct ipv6hdr *ipv6_hdr;
  struct tcam_entry *te;

  /* TCAM entry timeout handling - remove old entries from the table */
  uint64_t ts = hdr->ts.tv_sec * 1000000 + hdr->ts.tv_usec;
  while ((te = TAILQ_FIRST(&tcamfifo))) {
    if (te->ts + ttl <= ts) {
      TAILQ_REMOVE(&tcamfifo, te, link);
      TAILQ_REMOVE(&tcamtable[te->idx], te, node);
      free(te);
      num_tcam_entry--;
      assert(num_tcam_entry >= 0);
    }
    else
      break;
  }

  /* get Transport layer procotol */
  if (ether_type == ETH_P_IP) {
    ipv4_hdr = get_ipv4_hdr(pkt);
    protocol = ipv4_hdr->protocol;
  }
  else if (ether_type == ETH_P_IPV6) {
    ipv6_hdr = get_ipv6_hdr(pkt);
    protocol = ipv6_hdr->nexthdr;
  }
  else {
    return;
  }

  if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
    /* lookup TCAM table */
    te = tcamtable_lookup(pkt);
    if (te)
      return;
    
    /* no TCAM entry - insert a new TCAM entry to TCAM table and FIFO queue */
    te = (struct tcam_entry *)malloc(sizeof(struct tcam_entry));
    if (te == NULL) {
      perror("malloc");
      return;
    }

    if (ether_type == ETH_P_IP) {
      te->saddr.s6_addr32[0] = ipv4_hdr->saddr;
      te->daddr.s6_addr32[0] = ipv4_hdr->daddr;
    }
    else if (ether_type == ETH_P_IPV6) {
      te->saddr = ipv6_hdr->saddr;
      te->daddr = ipv6_hdr->daddr;
    }

    struct udphdr *udp_hdr = get_udp_hdr(pkt);

    te->sport = udp_hdr->source;
    te->dport = udp_hdr->dest;

    te->ts = ts;
    te->ether_type = ether_type;
    te->protocol = protocol;
    te->idx = get_hash(pkt);

    TAILQ_INSERT_HEAD(&tcamtable[te->idx], te, node);
    TAILQ_INSERT_TAIL(&tcamfifo, te, link);

    /* update TCAM entry counter */
    num_tcam_entry++;    
    if (max_tcam_entry < num_tcam_entry)
      max_tcam_entry = num_tcam_entry;
    num_query++;
  }
}
/******************************************************************************
 * Function: signal_handler
 * - Close opened files, free allocated memory and finish the program.
 */
static void
signal_handler(int signum) 
{
  int i;
  struct tcam_entry *te;

  if (signum != SIGINT)
    exit(1);

  /* close opened files */
  for (i = 0; i < NUM_DISK; i++)
    if (handle[i])
      pcap_close(handle[i]);

  /* free allocated memory */
  while ((te = TAILQ_FIRST(&tcamfifo))) {
    TAILQ_REMOVE(&tcamfifo, te, link);
    free(te);
  }

  exit(0);
}
/******************************************************************************
 * Function: find_oldest_pkt
 * - Find the oldest packet and return the index of it.
 */
static inline int
find_oldest_pkt(struct pcap_pkthdr hdr[], const u_char *pkt[]) 
{
  uint64_t t1, t2;
  int idx = -1;
  int i;

  for (i = 0; i < NUM_DISK; i++) {
    /* no more packets to see in this disk - skip */
    if (pkt[i] == NULL)
      continue;

    /* the first packet case */
    if (idx == -1) {
      idx = i;
      t1 = hdr[i].ts.tv_sec * 1000000 + hdr[i].ts.tv_usec;
      continue;
    }

    /* compare two arrival times and find the older one */
    t2 = hdr[i].ts.tv_sec * 1000000 + hdr[i].ts.tv_usec;
    if (t1 > t2) {
      idx = i;
      t1 = hdr[i].ts.tv_sec * 1000000 + hdr[i].ts.tv_usec;
    }
  }

  /* return the index of the oldest one */
  return idx;
}
/******************************************************************************
 * Function: main
 */
int
main(int argc, char *argv[])
{
  struct dirent **entry[NUM_DISK];
  int num[NUM_DISK];
  int first[NUM_DISK];
  int last[NUM_DISK];
  int idx[NUM_DISK];
  struct pcap_pkthdr hdr[NUM_DISK];
  const u_char *pkt[NUM_DISK];
  int i, j, ret;
  struct stat statbuf;
  struct tm *tm;
  int target_hour;
  char filename[32];
  char errbuf[PCAP_ERRBUF_SIZE];

  /* check the argument */
  if (argc != 3) {
    fprintf(stderr, "USAGE: %s [TARGET HOUR] [TIME TO LIVE]\n", argv[0]);
    fprintf(stderr, "TARGET HOUR: 0 ~ 23\n");
    fprintf(stderr, "TIME TO LIVE: 10 ~ 300000000 usec TCAM entry deadline\n");
    return 0;
  }

  /* get the target hour */
  target_hour = atoi(argv[1]);
  if (target_hour < 0 || target_hour > 23) {
    fprintf(stderr, "invalid TARGET HOUR\n");
    fprintf(stderr, "USAGE: %s [TARGET HOUR]\n", argv[0]);
    fprintf(stderr, "TARGET HOUR: 0 ~ 23\n");
    return 0;
  }

  /* get ttl */
  ttl = atoi(argv[2]);
  if (ttl < 0 || ttl > 300000000) {
    fprintf(stderr, "invalid TIME TO LIVE\n");
    fprintf(stderr, "USAGE: %s [TARGET HOUR] [TIME TO LIVE]\n", argv[0]);
    fprintf(stderr, "TARGET HOUR: 0 ~ 23\n");
    fprintf(stderr, "TIME TO LIVE: 10 ~ 300000000 usec TCAM entry deadline\n");
    return 0;
  }

  /* set interrupt handler */
  if (signal(SIGINT, signal_handler) == SIG_ERR) {
    perror("signal");
    return 0;
  }

  /* initialize TCAM lookup table and FIFO queue */
  for (i = 0; i < TCAM_LOOKUP_TABLE_SIZE; i++)
    TAILQ_INIT(&tcamtable[i]);
  TAILQ_INIT(&tcamfifo);

  /* make the list of files to check using timestamp */
  for (i = 0; i < NUM_DISK; i++)
    first[i] = -1;
  for (i = 0; i < NUM_DISK; i++) {
    num[i] = scandir(path[i], &entry[i], NULL, alphasort);
    for (j = 0; j < num[i]; j++) {
      sprintf(filename, "%s%s", path[i], (entry[i])[j]->d_name);
      if (stat(filename, &statbuf) == -1) {
	perror("stat");
	break;
      }

      /* find the first and last files having packets at the target hour */
      tm = localtime(&statbuf.st_ctime);
      if (tm->tm_hour == target_hour) {
	if (first[i] == -1)
	  first[i] = j;
	last[i] = j;
      }
    }
  }

  /* open the files and read the first packet of each file */
  for (i = 0; i < NUM_DISK; i++) {
    idx[i] = first[i];
    sprintf(filename, "%s%s", path[i], (entry[i])[first[i]]->d_name);
    handle[i] = pcap_open_offline(filename, errbuf);
    if (handle[i] == NULL) {
      perror("pcap_open_offline");
      continue;
    }
    pkt[i] = pcap_next(handle[i], &hdr[i]);
  }

  /* compare the arrival time of packets to find the oldest one */
  while ((ret = find_oldest_pkt(hdr, pkt)) != -1) {
    if (prev_t == 0)
      prev_t = hdr[ret].ts.tv_sec;

    /* process packet */
    process_packet(&hdr[ret], pkt[ret]);

    if (hdr[ret].ts.tv_sec > prev_t) {
      printf("%lu %"PRIu64" %"PRIu64" %"PRIu64"\n",
	     hdr[ret].ts.tv_sec, num_tcam_entry, max_tcam_entry,
	     num_query - prev_num_query);
      fprintf(stderr, "%lu %"PRIu64" %"PRIu64" %"PRIu64"\n",
	     hdr[ret].ts.tv_sec, num_tcam_entry, max_tcam_entry,
	     num_query - prev_num_query);
      prev_num_query = num_query;
      prev_t = hdr[ret].ts.tv_sec;
    }

    /* read the next packet */
    pkt[ret] = pcap_next(handle[ret], &hdr[ret]);
    if (pkt[ret] == NULL || hdr[ret].ts.tv_sec == 0) {
      pcap_close(handle[ret]);
      idx[ret]++;
      if (idx[ret] <= last[ret]) {
	sprintf(filename, "%s%s", path[ret], (entry[ret])[idx[ret]]->d_name);
	handle[ret] = pcap_open_offline(filename, errbuf);
	if (handle[ret] == NULL) {
	  perror("pcap_open_offline");
	  pkt[ret] = NULL;
	  continue;
	}
	pkt[ret] = pcap_next(handle[ret], &hdr[ret]);
      }
      else {
	pkt[ret] = NULL;
	handle[ret] = NULL;
      }
    }
  }

  /* close remaining pcap files */
  for (i = 0; i < NUM_DISK; i++) {
    if (handle[i])
      pcap_close(handle[i]);
  }

  /* free TCAM entries */
  struct tcam_entry *te;
  while ((te = TAILQ_FIRST(&tcamfifo))) {
    TAILQ_REMOVE(&tcamfifo, te, link);
    free(te);
  }

  return 0;
}
