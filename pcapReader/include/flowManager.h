#ifndef __FLOWMANAGER_H__
#define __FLOWMANAGER_H__

/******************************************************************************
 * Header files
 */
#include <stdint.h>
#include <sys/times.h>
#include <sys/types.h>

/******************************************************************************
 * ADT definitions
 */
enum {START, END};

enum FLOW_STATE {CLOSE, SYN, SYNACK, ESTABLISHED, FIN1, FIN2, RST};

struct flow {
  __u32 saddr;           /* source IP address of SYN packet */
  __u32 daddr;           /* destination IP address of SYN packet */
  __u16 sport;           /* source port number of SYN packet */
  __u16 dport;           /* destination port number of SYN packet */
  struct timeval ts[2];  /* start & end timestamp */
  enum FLOW_STATE state; /* TCP flow state */
  uint64_t num_byte;     /* the number of bytes of the flow */
  uint64_t num_pkt;      /* the number of packets of the flow */
};

#endif
