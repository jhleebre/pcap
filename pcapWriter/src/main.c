#ifndef _GNU_SOURCE
#define _GNU_SOURCE
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
#include <pthread.h>

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

#include "main.h"
#include "engine.h"
#include "macro.h"

/*****************************************************************************
 * Global variables
 */
bool done = false;
uint16_t num_port;
uint16_t num_hdd_per_lcore = NUM_HDD_PER_LCORE_DEFAULT;
uint16_t num_wbuf = NUM_WBUF_DEFAULT;
uint64_t size_wbuf = SIZE_WBUF_DEFAULT;
uint64_t size_pcap = SIZE_PCAP_FILE_DEFAULT;
engine_context_t eng_ctx[RTE_MAX_LCORE];
pthread_mutex_t main_mutex;

/*****************************************************************************
 * Static variables
 */
static uint16_t num_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t num_txd = RTE_TEST_TX_DESC_DEFAULT;
static uint16_t num_rxq;
static uint16_t num_txq = 1;
static uint16_t num_lcore;
static int print_period = PRINT_PERIOD_DEFAULT;
static uint64_t prev_byte = 0;
static uint64_t prev_pkt = 0;
struct rte_eth_stats prev_stats[RTE_MAX_ETHPORTS];
static struct timeval init_ts;
static struct timeval prev_ts;
/* key for symmetric RSS hashing */
static uint8_t key[] = {
  0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
  0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
  0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
  0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
};
static const struct rte_eth_conf port_conf = {
  .rxmode = {
    .mq_mode = ETH_MQ_RX_RSS,
    .split_hdr_size = 0,
    .header_split = 0,   /**< Header Split disabled */
    .hw_ip_checksum = 0, /**< IP checksum offload disabled */
    .hw_vlan_filter = 0, /**< VLAN filtering disabled */
    .jumbo_frame = 0,    /**< Jumbo Frame Support disabled */
    .hw_strip_crc = 0,   /**< CRC stripped by hardware */
  },
  .rx_adv_conf = {
    .rss_conf = {
      .rss_key = key,
      .rss_key_len = 40,
      .rss_hf = ETH_RSS_IP,
    },
  },
  .txmode = {
    .mq_mode = ETH_MQ_TX_NONE,
  },
};

/******************************************************************************
 * Function prototypes
 */
static inline void   pcapWriter_init(int argc, char **argv);
static inline int    pcapWriter_parse_args(char *app_name,
					   int argc, char **argv);
static inline void   pcapWriter_print_status(void);
static inline void   pcapWriter_print_usage(char *app_name);
static inline double get_time_diff_sec(struct timeval *ct, struct timeval *pt);
static        void   signal_handler(int signum);

/******************************************************************************
 * Function: main
 * - Main procedure of the application
 * - Initialize DPDK module and master & slave lcores
 * - Run lcores and print statistics periodically
 */
int
main(int argc, char **argv)
{
  unsigned lcore_id;

  /* init DPDK module and application */
  pcapWriter_init(argc, argv);

  /* set interrupt handler */
  signal(SIGINT, signal_handler);

  /* init main mutex for synchronization */
  pthread_mutex_init(&main_mutex, NULL);

  /* launch per-lcore init on every lcore */
  RTE_LCORE_FOREACH_SLAVE(lcore_id) {
    pthread_mutex_lock(&main_mutex);
    printf("\n[MASTER   ] launch: ENGINE-%02u\n", lcore_id);
    if (rte_eal_remote_launch(engine_main, NULL, lcore_id) < 0)
      return -1;
  }
  pthread_mutex_lock(&main_mutex);
  pthread_mutex_unlock(&main_mutex);

  printf("================================================================\n");

  /* collect and print lcore statistics periodically */
  gettimeofday(&init_ts, NULL);
  prev_ts = init_ts;
  sleep(print_period);
  while (!done) {
    if (print_period) {
      pcapWriter_print_status();
      sleep(print_period);
    }
    else
      sleep(PRINT_PERIOD_MAX);
  }

  /* wait until the end of every slave */
  RTE_LCORE_FOREACH_SLAVE(lcore_id) {
    if (rte_eal_wait_lcore(lcore_id) < 0)
      return -1;
    printf("[MASTER   ] terminated: ENGINE-%02u\n", lcore_id);
  }
  printf("[MASTER   ] terminated: MASTER\n");

  return 0;
}

/******************************************************************************
 * Function: pcapWriter_init
 * - Initialize DPDK module and application
 */
static inline void
pcapWriter_init(int argc, char **argv)
{
  int ret;
  int port_id;
  int rxq_id;
  char *app_name = argv[0];

  /* init EAL */
  ret = rte_eal_init(argc, argv);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
  argc -= ret;
  argv += ret;

  num_lcore = rte_lcore_count();
  num_rxq = num_lcore - 1;

  /* parse application arguments (after the EAL ones) */
  ret = pcapWriter_parse_args(app_name, argc, argv);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Invalid PCAPWRITER arguments\n");

  /* get the number of the Ethernet ports */
  num_port = rte_eth_dev_count();
  //num_port = 1;
  if (num_port == 0)
    rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");
  if (num_port > RTE_MAX_ETHPORTS)
    num_port = RTE_MAX_ETHPORTS;

  struct rte_mempool *pktmbuf_pool[num_port][num_rxq];
  struct ether_addr port_eth_addr[num_port];

  /* create the mbuf pool */
  for (port_id = 0; port_id < num_port; port_id++) {
    for (rxq_id = 0; rxq_id < num_rxq; rxq_id++) {
      char name[32];
      sprintf(name, "mbuf_pool_%d_%d", port_id, rxq_id);
      pktmbuf_pool[port_id][rxq_id] =
	rte_pktmbuf_pool_create(name, NUM_MBUF, MBUF_CACHE_SIZE,
				0, RTE_MBUF_DEFAULT_BUF_SIZE,
				rte_lcore_to_socket_id(rxq_id + 1));
      if (pktmbuf_pool[port_id][rxq_id] == NULL)
	rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
    }
  }

  /* initialize each port */
  for (port_id = 0; port_id < num_port; port_id++) {
    /* init port */
    printf("Initializing port %u... ", (unsigned) port_id);
    fflush(stdout);
    ret = rte_eth_dev_configure(port_id, num_rxq, num_txq, &port_conf);
    if (ret < 0)
      rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
	       ret, (unsigned)port_id);
    
    rte_eth_macaddr_get(port_id, &port_eth_addr[port_id]);

    /* init RX queues */
    fflush(stdout);
    for (rxq_id = 0; rxq_id < num_rxq; rxq_id++) {
      ret = rte_eth_rx_queue_setup(port_id, rxq_id, num_rxd, 
				   rte_eth_dev_socket_id(port_id),
				   NULL, pktmbuf_pool[port_id][rxq_id]);
      if (ret < 0)
	rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err=%d, port=%u\n",
		 ret, (unsigned)port_id);
    }

    /* init TX queues */
    fflush(stdout);
    ret = rte_eth_tx_queue_setup(port_id, 0, num_txd,
				 rte_eth_dev_socket_id(port_id), NULL);
    if (ret < 0)
      rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%d, port=%u\n",
	       ret, (unsigned)port_id);
    
    /* start device */
    ret = rte_eth_dev_start(port_id);
    if (ret < 0)
      rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%u\n",
	       ret, (unsigned)port_id);

    printf("done: \n");

    rte_eth_promiscuous_enable(port_id);
    
    printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
	   (unsigned)port_id,
	   port_eth_addr[port_id].addr_bytes[0],
	   port_eth_addr[port_id].addr_bytes[1],
	   port_eth_addr[port_id].addr_bytes[2],
	   port_eth_addr[port_id].addr_bytes[3],
	   port_eth_addr[port_id].addr_bytes[4],
	   port_eth_addr[port_id].addr_bytes[5]);
  }
}

/******************************************************************************
 * Function: pcapWriter_parse_args
 * - Parse application arguments after the EAL ones
 * - Nothing to do in the current version
 */
static inline int
pcapWriter_parse_args(char *app_name, int argc, char **argv)
{
  int opt;
  int ret;
  long long retll;

  while ((opt = getopt(argc, argv, "d:t:b:s:p:")) != EOF) {
    switch (opt) {
    case 'd':			/* the number of hard disks for each lcore */
      ret = atoi(optarg);
      if (ret < 0 || ret > NUM_HDD_PER_LCORE_MAX) {
	fprintf(stderr, "invalid number of hard disks per lcore: %d\n", ret);
	pcapWriter_print_usage(app_name);
	return -1;
      }
      printf("The number of hard disks per lcore: %d\n", ret);
      num_hdd_per_lcore = ret;
      break;
    case 't':			/* status print period */
      ret = atoi(optarg);
      if (ret < 0 || ret > PRINT_PERIOD_MAX) {
	fprintf(stderr, "invalid print period: %d\n", ret);
	pcapWriter_print_usage(app_name);
	return -1;
      }
      printf("The print period: %d\n", ret);
      print_period = ret;
      break;
    case 'b':			/* the number of writer buffers */
      ret = atoi(optarg);
      if (ret < NUM_WBUF_MIN || ret > NUM_WBUF_MAX) {
	fprintf(stderr, "invalid number of writer buffers: %d\n", ret);
	pcapWriter_print_usage(app_name);
	return -1;
      }
      printf("The number of writer buffers: %d\n", ret);
      num_wbuf = ret;
      break;
    case 's':			/* the size of writer buffers */
      retll = atoll(optarg);
      if (retll < SIZE_WBUF_MIN || retll > SIZE_WBUF_MAX ||
	  !is_multiple_of_512(retll)) {
	fprintf(stderr, "invalid wbuf size: %lld\n", retll);
	pcapWriter_print_usage(app_name);
	return -1;
      }
      printf("The size of the writer buffer: %lld\n", retll);
      size_wbuf = retll;
      break;
    case 'p':			/* the size of pcap files */
      retll = atoll(optarg);
      if (retll < SIZE_PCAP_FILE_MIN || retll > SIZE_PCAP_FILE_MAX) {
	fprintf(stderr, "invalid pcap file size: %lld\n", retll);
	pcapWriter_print_usage(app_name);
	return -1;
      }
      printf("The size of the pcap file: %lld\n", retll);
      size_pcap = retll;
      break;
    default:
      pcapWriter_print_usage(app_name);
      return -1;
    }
  }

  return 0;
}

/******************************************************************************
 * Function: pcapWriter_print_usage
 * - Print command usage
 */
static inline void
pcapWriter_print_usage(char *app_name)
{
  fprintf(stderr, "Usage: %s [EAL options]"
	  " -- [-d NUM_HDD_PER_LCORE] [-t PERIOD] [-b NUM_WBUF]"
	  " [-s SIZE_WBUF] [-p SIZE_PCAP]\n"
	  "  -d NUM_HDD_PER_LCORE:"
	  " the number of hard disks for each lcore"
	  " (0 to disable disk writing, %d default, %d maximum)\n"
	  "  -t PERIOD:"
	  " statistics will be printed each PERIOD second"
	  " (0 to disable, %d default, %d maximum)\n"
	  "  -b NUM_WBUF:"
	  " the number of writer buffers for each writer"
	  " (%d minimum, %d default, %d maximum)\n"
	  "  -s SIZE_WBUF:"
	  " the size of each writer buffer"
	  " (%lld minimum, %lld default, %lld maximum,"
	  " should be a multiple of 512)\n"
	  "  -p SIZE_PCAP:"
	  " the size of each pcap file"
	  " (%lld minimum, %lld default, %lld maximum)\n",
	  app_name,
	  NUM_HDD_PER_LCORE_DEFAULT, NUM_HDD_PER_LCORE_MAX,
	  PRINT_PERIOD_DEFAULT, PRINT_PERIOD_MAX,
	  NUM_WBUF_MIN, NUM_WBUF_DEFAULT, NUM_WBUF_MAX,
	  SIZE_WBUF_MIN, SIZE_WBUF_DEFAULT, SIZE_WBUF_MAX,
	  SIZE_PCAP_FILE_MIN, SIZE_PCAP_FILE_DEFAULT, SIZE_PCAP_FILE_MAX);
}
/******************************************************************************
 * Function: pcapWriter_print_status
 * - Collect and print lcore statistics
 */
static inline void
pcapWriter_print_status(void)
{
  uint64_t curr_byte = 0, curr_pkt = 0, diff_byte, diff_pkt, tot_byte;
  struct timeval curr_ts;
  int lcore_id;
  double elapsed, uptime;
  int day, hour, min, sec;

  gettimeofday(&curr_ts, NULL);

  /* collect the status */
  for (lcore_id = 1; lcore_id < num_lcore; lcore_id++) {
    curr_byte += eng_ctx[lcore_id]->num_byte;
    curr_pkt  += eng_ctx[lcore_id]->num_pkt;
  }  

  /* calculate the difference */
  diff_byte = curr_byte - prev_byte;
  diff_pkt  = curr_pkt  - prev_pkt;
  tot_byte = diff_byte + diff_pkt * 24;

  /* calculate the time */
  elapsed = get_time_diff_sec(&curr_ts, &prev_ts);
  uptime  = get_time_diff_sec(&curr_ts, &init_ts);

  sec  = ((int) uptime) % 60;
  min  = (((int)uptime) / 60)   % 60;
  hour = (((int)uptime) / 3600) % 24;
  day  = ((int) uptime) / 86400;

  printf("-------------------------------------------------------------------------------\n");

  /* print the status */
  printf("Uptime     : %2d:%2d:%2d:%2d\n", day, hour, min, sec);
  //printf("%5.2f Gbps\n", gbps(diff_byte, elapsed));
  printf("Bytes/sec  : %5.2f (%5.2f) Gbps\n",
	 gbps(diff_byte, elapsed), gbps(tot_byte, elapsed));
  //for (lcore_id = 1; lcore_id < num_lcore; lcore_id++) {
    //printf("%5.2f ", gbps(eng_ctx[lcore_id]->num_byte, elapsed));
  //}
  printf("Pkts/sec   : %5.2f Mpps\n", mpps(diff_pkt, elapsed));
  printf("Total bytes: %5.2f GBytes\n", curr_byte * 1e-9);
  printf("Total pkts : %5.2f MPkts\n", curr_pkt * 1e-6);

  uint8_t port_id;
  struct rte_eth_stats curr_stats[num_port];
  for (port_id = 0; port_id < num_port; port_id++) {
    rte_eth_stats_get(port_id, &curr_stats[port_id]);
    printf("eth%"PRIu8" %"PRIu64" pps %"PRIu64" Bps"
	   " missed: %"PRIu64" pps errors: %"PRIu64" pps\n",
	   port_id, 
	   curr_stats[port_id].ipackets - prev_stats[port_id].ipackets, 
	   curr_stats[port_id].ibytes   - prev_stats[port_id].ibytes, 
	   curr_stats[port_id].imissed  - prev_stats[port_id].imissed, 
	   curr_stats[port_id].ierrors  - prev_stats[port_id].ierrors);
    

    prev_stats[port_id] = curr_stats[port_id];
  }
  
  prev_byte = curr_byte;
  prev_pkt  = curr_pkt;
  prev_ts   = curr_ts;
}

/******************************************************************************
 * Function: get_time_diff_sec
 * - Get the time difference beween two timestamp
 * - The first timestamp should be later than the second one
 */
static inline double
get_time_diff_sec(struct timeval *ct, struct timeval *pt)
{
  return (((double)ct->tv_sec + 1e-6 * (double)ct->tv_usec) - 
	  ((double)pt->tv_sec + 1e-6 * (double)pt->tv_usec));
}

/******************************************************************************
 * Function: signal_handler
 * - Interrupt handler for the application
 */
static void
signal_handler(int signum)
{
  if (signum != SIGINT)
    rte_exit(EXIT_FAILURE, "received signal: %d, exiting\n", signum);

  printf("================================================================\n");
  
  done = true;
}
