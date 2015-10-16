#ifndef __MAIN_H__
#define __MAIN_H__

#include <stdint.h>

/* DPDK configurations */
#define NUM_MBUF                 8192
#define MAX_PKT_BURST            32
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512
#define MBUF_CACHE_SIZE          32

/* disk configurations */
#define NUM_HDD_PER_LCORE_DEFAULT 2 /* zero for sniffing mode */
#define NUM_HDD_PER_LCORE_MAX     32
#define NUM_PCAP_PER_DISK_MAX     1500

/* pcap file configurations */
#define SIZE_PCAP_FILE_MIN     1048576ll     /*  1 MiB */
#define SIZE_PCAP_FILE_DEFAULT 1073741824ll  /*  1 GiB */
#define SIZE_PCAP_FILE_MAX     17179869184ll /* 16 GiB */

/* statistics print configurations */
#define PRINT_PERIOD_DEFAULT 1	/* 0 for quite mode (no printing) */
#define PRINT_PERIOD_MAX     86400

/* writer buffer configurations */
#define NUM_WBUF_MIN      1
#define NUM_WBUF_DEFAULT  1024
#define NUM_WBUF_MAX      4096
#define SIZE_WBUF_MIN     4096ll
#define SIZE_WBUF_DEFAULT 131072ll
#define SIZE_WBUF_MAX     4194304ll

enum {ENGINE, WRITER, PCAP};
#define SIG_WRT_CLOSE 1
#define SIG_WRT_CONT  2

struct lcore_statistics {
  uint64_t num_byte;
  uint64_t num_pkt;
} __rte_cache_aligned;

#endif
