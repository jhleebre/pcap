#ifndef __FLOWMANAGER_H__
#define __FLOWMANAGER_H__

/******************************************************************************
 * Header files
 */
#include <stdint.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <linux/in6.h>
#include <pcap.h>

/******************************************************************************
 * ADT definitions
 */
enum {FIRST, LAST};

//enum FLOW_STATE {CLOSE, SYN, SYNACK, ESTABLISHED,
//		 FIN1, FIN2, RST, UNCLEAR, UNCLEAR_FIN};

struct flow {
  struct in6_addr saddr;  /* source IP address of the first packet */
  struct in6_addr daddr;  /* destination IP address of the first packet */
  __u16 sport;            /* source port number of the first packet */
  __u16 dport;            /* destination port number of the first packet */
  struct timeval ts[2];   /* the arriving times of the first & last packets */
  //enum FLOW_STATE state;  /* TCP flow state */
  uint64_t num_byte;      /* the number of bytes of the flow */
  uint64_t num_pkt;       /* the number of packets of the flow */
  TAILQ_ENTRY(flow) node; /* flowTable entry */
  uint16_t ether_type;	  /* IPv4 or IPv6 (or something else?) */
};
typedef struct flow *flow_t;
typedef TAILQ_HEAD(table, flow) flowQueue;
struct flowTable {
  flowQueue table[FLOW_TABLE_SIZE];
};
typedef struct flowTable *flowTable_t;
  
/******************************************************************************
 * Function prototypes
 */
inline flowTable_t flowTable_create(void);
inline void        flowTable_destroy(flowTable_t ft);
inline flow_t      flowTable_lookup(flowTable_t ft, const u_char *pkt);
inline flow_t      flowTable_create_flow(flowTable_t ft,
					 struct pcap_pkthdr *hdr, 
					 const u_char *pkt);
inline void        flowTable_update_flow(flowTable_t ft, flow_t f,
					 struct pcap_pkthdr *hdr,
					 const u_char *pkt);

#endif
