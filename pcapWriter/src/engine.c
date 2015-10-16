#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef __USE_FILE_OFFSET64
#define __USE_FILE_OFFSET64
#endif

/*****************************************************************************
 * Header files
 * - may need to remove redundant header files
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <errno.h>
#include <pcap.h>
#include <assert.h>

#include <rte_common.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_mempool.h>
#include <rte_byteorder.h>

#include <linux/ip.h>
#include <linux/udp.h>

#include "main.h"
#include "engine.h"
#include "macro.h"

/******************************************************************************
 * Global variables
 */
extern bool done;
extern uint16_t num_port;
extern uint16_t num_hdd_per_lcore;
extern uint16_t num_wbuf;
extern uint64_t size_wbuf;
extern uint64_t size_pcap;
extern engine_context_t eng_ctx[RTE_MAX_LCORE];
extern pthread_mutex_t main_mutex;

static const struct pcap_file_header pfh = {
  .magic         = 0xa1b2c3d4,
  .version_major = 2,
  .version_minor = 4,
  .thiszone      = 0,
  .sigfigs       = 0,
  .snaplen       = 65535,
  .linktype      = 1,
};

struct my_pcap_pkthdr {
  uint32_t sec;
  uint32_t usec;
  uint32_t caplen;
  uint32_t len;
};

/******************************************************************************
 * Function prototypes
 */
static inline int  engine_init(engine_context_t ectx, writer_t wrt);
static inline void engine_clear(engine_context_t ectx);
static inline int  engine_process_packet(engine_context_t ectx,
					 struct rte_mbuf *m,
					 struct my_pcap_pkthdr *hdr);
static inline int engine_write_packet(engine_context_t ectx,
				      u_char *eth_frame,
				      struct my_pcap_pkthdr *hdr);
static inline int engine_get_writer(u_char *eth_frame);
static inline writer_buffer_t engine_get_wbuf(writer_context_t wctx, int len);
static inline writer_buffer_t engine_get_next_wbuf(writer_context_t wctx);
static inline unsigned int engine_copy_to_wbuf(writer_context_t wctx,
					       u_char *data, int len);

/******************************************************************************
 * Function: engine_main
 * - Main procedure of each Poll Mode Driver (PMD)
 * - Read packets from NIC ports and process each of them
 */
int
engine_main(__attribute__((unused)) void *dummy)
{
  struct rte_mbuf *pkt_burst[MAX_PKT_BURST];
  struct rte_mbuf *m;
  struct engine_context ectx;
  struct writer wrt[num_hdd_per_lcore];
  int lcore_id, port_id, num_rx, mbuf_id;
  struct my_pcap_pkthdr hdr;

  lcore_id = rte_lcore_id();
  eng_ctx[lcore_id] = &ectx;

  /* init engine */
  if (engine_init(&ectx, wrt) == -1) {
    fprintf(stderr, "[ENGINE-%02u] engine initialization failure\n", lcore_id);
    return 1;
  }
  
  printf("[ENGINE-%02u] engine initialization: done\n", lcore_id);
  
  pthread_mutex_unlock(&main_mutex);

  while (!done) {
    /* read packets from RX queues */
    for (port_id = 0; port_id < num_port; port_id++) {
      num_rx = rte_eth_rx_burst((uint8_t)port_id, (uint16_t)lcore_id - 1,
				pkt_burst, MAX_PKT_BURST);
      /* skip if there are no packets */
      if (num_rx == 0)
	continue;

      /* get the arrival time */
      struct timeval t;
      gettimeofday(&t, NULL);
      hdr.sec  = t.tv_sec;
      hdr.usec = t.tv_usec;
    
      /* process packets one by one */
      for (mbuf_id = 0; mbuf_id < num_rx; mbuf_id++) {
	m = pkt_burst[mbuf_id];
	rte_prefetch0(rte_pktmbuf_mtod(m, void *)); /* XXX: need to optimize prefetching more*/
	hdr.len = rte_pktmbuf_pkt_len(m);
	hdr.caplen = hdr.len;
	
	if (num_hdd_per_lcore > 0)
	  if (engine_process_packet(&ectx, m, &hdr) < 0)
	    continue;
	
	ectx.num_byte += hdr.len;
	ectx.num_pkt++;
	
	/* free the packet after processing */
	rte_pktmbuf_free(m);
      }
    }
  }

  /* clean up before finish */
  engine_clear(&ectx);

  return 0;
}

/******************************************************************************
 * Function: engine_init
 * - Initialize engine and run writer threads
 */
static inline int 
engine_init(engine_context_t ectx, writer_t wrt)
{
  int writer_id;
  int num_writer = 0;

  /* init engine context */
  ectx->num_byte = 0;
  ectx->num_pkt  = 0;
  ectx->wrt = wrt;
  ectx->lcore_id = rte_lcore_id();
  pthread_mutex_init(&ectx->mutex, NULL);

  /* run writer threads */
  for (writer_id = 0; writer_id < num_hdd_per_lcore; writer_id++) {
    pthread_mutex_lock(&ectx->mutex);

    /* create socket pair to send signal to writer */
    writer_t wrt_ptr = &wrt[writer_id];
    if (socketpair(AF_UNIX, SOCK_STREAM, AF_LOCAL, wrt_ptr->sockd) < 0) {
      perror("socketpair");
      return -1;
    }
    wrt_ptr->cpu = ectx->lcore_id;
    wrt_ptr->ectx = ectx;
    wrt_ptr->disk_id = (ectx->lcore_id - 1) * num_hdd_per_lcore + writer_id;

    /* create writer thread */
    if (pthread_create(&wrt_ptr->thread, NULL, writer_main, (void *)wrt_ptr)) {
      perror("pthread_create");
      return -1;
    }

    /* wait until the end of writer thread creation and initialization */
    pthread_mutex_lock(&ectx->mutex);
    pthread_mutex_unlock(&ectx->mutex);

    num_writer++;

    /* set the pcap file header */
    writer_buffer_t  wbuf = engine_get_wbuf(wrt_ptr->wctx, 0);
    assert(wbuf);
    assert(wbuf->buf);

    memcpy(wbuf->buf, &pfh, sizeof(struct pcap_file_header));
    wbuf->len = sizeof(struct pcap_file_header);
  }
  
  return num_writer;
}

/******************************************************************************
 * Function: engine_clear
 * - Clean-up function of an engine
 */
static inline void 
engine_clear(engine_context_t ectx)
{
  int writer_id;
  int sig = -1;

  for (writer_id = 0; writer_id < num_hdd_per_lcore; writer_id++) {
    printf("[ENGINE-%02u] terminate writer-%d...\n", ectx->lcore_id,
	   (ectx->lcore_id - 1) * num_hdd_per_lcore + writer_id + 1);
    /* send signal to the writer to terminate it */
    if (write(ectx->wrt[writer_id].sockd[ENGINE], &sig, sizeof(int))
	!= sizeof(int))
      rte_exit(EXIT_FAILURE, "write\n");
    pthread_join(ectx->wrt[writer_id].thread, NULL);
  }
}

/******************************************************************************
 * Function: engine_process_packet
 * - Decode a packet and process it according to its protocol
 */
static inline int
engine_process_packet(engine_context_t ectx, struct rte_mbuf *m,
		      struct my_pcap_pkthdr *hdr)
{
  return engine_write_packet(ectx, rte_pktmbuf_mtod(m, u_char *), hdr);
}

/******************************************************************************
 * Function: engine_write_packet
 * - Write a packet to disk
 * - This function copy the Ethernet frame to the writer buffer
 */
static inline int
engine_write_packet(engine_context_t ectx, u_char *eth_frame,
		    struct my_pcap_pkthdr *hdr)
{
  int writer_id = engine_get_writer(eth_frame);
  writer_context_t wctx = ectx->wrt[writer_id].wctx;
  writer_buffer_t wbuf;

  /* get a writer buffer to copy the packet */
  wbuf = engine_get_wbuf(wctx, sizeof(struct my_pcap_pkthdr) + hdr->len);
  if (wbuf == NULL) {
    perror("engine_get_wbuf");
    return -1;
  }

  /* copy the pcap packet header to the writer buffer */
  if (engine_copy_to_wbuf(wctx, (u_char *)hdr, sizeof(struct my_pcap_pkthdr))
      != sizeof(struct my_pcap_pkthdr)) {
    perror("engine_copy_to_wbuf");
    return -1;
  }

  /* copy the packet to the writer buffer */
  if (engine_copy_to_wbuf(wctx, eth_frame, hdr->caplen) != hdr->caplen) {
    perror("engine_copy_to_wbuf");
    return -1;
  }

  return 0;
}

/******************************************************************************
 * Function: engine_get_writer
 * - Get an ID of a writer to write a packet
 */
static inline int
engine_get_writer(u_char *eth_frame)
{
  struct ether_hdr *eth_hdr = (struct ether_hdr *)eth_frame;
  struct vlan_hdr  *vlanhdr = NULL;
  struct iphdr     *ipv4_hdr;
  struct udphdr    *udp_hdr;
  struct ipv6_hdr  *ipv6hdr;
  uint16_t ether_type;
  uint16_t offset = sizeof(struct ether_hdr);
  uint32_t ret = 5381;
  int i;

  /* no need to select a writer (zero or one writer for each lcore) */
  if (num_hdd_per_lcore < 2)
    return 0;

  /* get the L3 protocol */
  ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
  if (ether_type == ETHER_TYPE_VLAN) {
    vlanhdr = (struct vlan_hdr *)(eth_frame + offset);
    ether_type = rte_be_to_cpu_16(vlanhdr->eth_proto);
    offset += sizeof(struct vlan_hdr);
  }
  
  /* non-directional hash function */
  switch (ether_type) {
  case ETHER_TYPE_IPv4:
    ipv4_hdr = (struct iphdr*)(eth_frame + offset);
    ret = ntohl(ipv4_hdr->saddr) + ntohl(ipv4_hdr->daddr);
    if (ipv4_hdr->protocol == IPPROTO_TCP ||
	ipv4_hdr->protocol == IPPROTO_UDP) {
      udp_hdr  = (struct udphdr*)(eth_frame + offset
				  + (ipv4_hdr->ihl << 2));
      ret += ntohs(udp_hdr->source) + ntohs(udp_hdr->dest);
    }
    break;
  case ETHER_TYPE_IPv6:
    ipv6hdr = (struct ipv6_hdr *)(eth_frame + offset);
    for (i = 0; i < 16; i++) {
      ret += ipv6hdr->src_addr[i] + ipv6hdr->dst_addr[i];
      ret <<= 3;
    }
    break;
  default:
    /*
    printf("Non-IP Ethernet frame - Ethertype: %s%u\n",
	   vlanhdr != NULL ? "[VLAN] " : "", ether_type);
    */
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
      ret += eth_hdr->d_addr.addr_bytes[i] + eth_hdr->s_addr.addr_bytes[i];
      ret <<= 3;
    }
    break;
  };

  return (ret % num_hdd_per_lcore);
}

/******************************************************************************
 * Function: engine_get_wbuf
 * - Get a writer buffer to write LEN bytes of data
 */
static inline writer_buffer_t
engine_get_wbuf(writer_context_t wctx, int len)
{
  writer_buffer_t wbuf = (wctx->wbuf_ptr ?
			  wctx->wbuf_ptr : 
			  engine_get_next_wbuf(wctx));
  int sig = SIG_WRT_CLOSE;

  /* no need to write something */
  if (len == 0)
    return wbuf;

  /* the current pcap file is almost full
     need to close the current file and prepare the next pcap file */
  if (wctx->num_byte_engine + wbuf->len + len > size_pcap) {
    /* fill zero to the end of the current writer buffer */
    memset(wbuf->buf + wbuf->len, 0, size_wbuf - wbuf->len);
    wbuf->len = size_wbuf;

    /* let the writer writes the writer buffer */
    wbuf->owner = WRITER;
    if (write(wctx->sockd[ENGINE], &sig, sizeof(int)) != sizeof(int)) {
      perror("write");
      return NULL;
    }

    /* reset file byte counter */
    wctx->num_byte_engine = 0;

    /* get a new writer buffer */
    if ((wbuf = engine_get_next_wbuf(wctx)) == NULL) {
      perror("engine_get_next_wbuf");
      return NULL;
    }

    /* write pcap file header to the writer buffer */
    memcpy(wbuf->buf, &pfh, sizeof(struct pcap_file_header));
    wbuf->len = sizeof(struct pcap_file_header);
  }

  /* check whether the next writer buffer is available if it is needed */
  if (wbuf->len + len > size_wbuf) {
    if (wctx->wbuf[wctx->wbuf_id].owner == WRITER) {
      fprintf(stderr, "no available writer buffer\n");
      return NULL;
    }
  }

  return wbuf;
}

/******************************************************************************
 * Function: engine_get_next_wbuf
 * - Get the next writer buffer
 */
static inline writer_buffer_t
engine_get_next_wbuf(writer_context_t wctx)
{
  writer_buffer_t wbuf = &wctx->wbuf[wctx->wbuf_id];

  /* check the ownership */
  if (wbuf->owner == WRITER)
    return NULL;

  /* update writer buffer ID to use later */
  wctx->wbuf_id = (wctx->wbuf_id + 1) % num_wbuf;

  /* clear writer buffer context to use */
  wbuf->len = 0;
  wctx->wbuf_ptr = wbuf;

  return wbuf;
}

/******************************************************************************
 * Function: engine_copy_to_wbuf
 * - Copy LEN byte of DATA to the current writer buffer
 */
static inline unsigned int
engine_copy_to_wbuf(writer_context_t wctx, u_char *data, int len)
{
  writer_buffer_t wbuf = wctx->wbuf_ptr;
  int left = size_wbuf - wbuf->len;
  int off = 0;
  int sig;

  assert(left >= 0); /* XXX: may need more graceful error handling */

  if (left < len) {
    /* fill the current writer buffer and give it to writer */
    memcpy(wbuf->buf + wbuf->len, data, left);
    wbuf->len += left;
    wbuf->owner = WRITER;
    sig = SIG_WRT_CONT;
    if (write(wctx->sockd[ENGINE], &sig, sizeof(int)) != sizeof(int)) {
      perror("write");
      return 0;
    }
    wctx->num_byte_engine += wbuf->len;

    /* get a new writer buffer */
    wbuf = engine_get_next_wbuf(wctx);
    assert(wbuf); /* XXX: may need more graceful error handling */
    wctx->wbuf_ptr = wbuf;

    len -= left;
    off = left;
  }

  /* write remains of data */
  if (len) {
    memcpy(wbuf->buf + wbuf->len, data + off, len);
    wbuf->len += len;
  }

  return len + off;
}
