#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef __USE_FILE_OFFSET64
#define __USE_FILE_OFFSET64
#endif

/******************************************************************************
 * Header files
 * - may need to remove redundant header files
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <fcntl.h>
#include <unistd.h>

#include "main.h"
#include "engine.h"
#include "writer.h"
#include "cpu.h"

/******************************************************************************
 * Global variables
 */
extern bool done;
extern uint16_t num_wbuf;
extern uint64_t size_wbuf;

/******************************************************************************
 * Function prototypes
 */
static inline int  writer_init(writer_context_t wctx, writer_t wrt,
			       writer_buffer_t wbuf);
static inline int  writer_read_file_id(writer_context_t wctx);
static inline int  writer_write_file_id(writer_context_t wctx);

static inline void writer_loop(writer_context_t wctx);
static inline void writer_clear(writer_context_t wctx);
static inline int  writer_open_pcap_file(writer_context_t wctx);

/******************************************************************************
 * Function: writer_main
 * - Main procesure of each writer thread
 * - Write buffered packet data to its disk continuously
 */
void *
writer_main(void *arg)
{
  writer_t wrt = (writer_t)arg;
  struct writer_buffer wbuf[num_wbuf];
  struct writer_context wctx;

  /* set CPU affinity */
  //bind_cpu(wrt->cpu);
  bind_cpu(0);

  /* init writer */
  if (writer_init(&wctx, wrt, wbuf) < 0) {
    fprintf(stderr, "[WRITER-%02u] writer initialization: fail\n", 
	    wrt->disk_id);
    pthread_exit(NULL);
  }

  /* lock current memory */
  if (mlockall(MCL_CURRENT) < 0)
    perror("mlockall");

  printf("[WRITER-%02u] writer initialization: done\n", wrt->disk_id);

  /* unlock to allow engine to process the next job */
  pthread_mutex_unlock(&wrt->ectx->mutex);

  /* write buffered packet data to the disk continuously */
  writer_loop(&wctx);

  /* clean up before finish */
  writer_clear(&wctx);

  pthread_exit(NULL);
}

/******************************************************************************
 * Function: writer_init
 * - Initialize writer
 */
static inline int
writer_init(writer_context_t wctx, writer_t wrt, writer_buffer_t wbuf)
{
  int wbuf_id;

  /* init writer context */
  wrt->wctx             = wctx;
  wctx->sockd[ENGINE]   = wrt->sockd[ENGINE];
  wctx->sockd[WRITER]   = wrt->sockd[WRITER];
  wctx->disk_id         = wrt->disk_id;
  wctx->wbuf            = wbuf;
  wctx->wbuf_ptr        = NULL;
  wctx->wbuf_id         = 0;
  wctx->num_byte_engine = 0;
  wctx->num_byte_writer = 0;
  wctx->num_byte_pcap   = 0;

  /* read the ID of the last file at the last dump */
  if (writer_read_file_id(wctx) != 0) {
    perror("writer_read_file_id");
    return -1;
  }

  /* allocate writer buffers */
  for (wbuf_id = 0; wbuf_id < num_wbuf; wbuf_id++) {
    if (posix_memalign((void**)&wbuf[wbuf_id].buf, getpagesize(), size_wbuf)) {
      perror("posix_memalign");
      return -1;
    }
  }

  /* open a new pcap file */
  if ((wctx->fd = writer_open_pcap_file(wctx)) == -1) {
    perror("writer_open_pcap_file");
    return -1;    
  }
  
  return 0;
}

/******************************************************************************
 * Function: writer_read_file_id
 * - Read file ID from meta file
 */
static inline int
writer_read_file_id(writer_context_t wctx)
{
  char file_name[128];
  FILE *fp;

  sprintf(file_name, "/mnt/meta_01/work_%02d.meta", wctx->disk_id + 1);
  if ((fp = fopen(file_name, "r")) == NULL) {
    wctx->file_id = -1; 
    wctx->old_file_id = 0;
  }
  else {
    if (fscanf(fp, "%d\n%d\n", &wctx->file_id, &wctx->old_file_id) != 2) {
      perror("fscanf");
      fclose(fp);
      return -1;
    }
    fclose(fp);
  }
  return 0;
}

/******************************************************************************
 * Function: writer_write_file_id
 * - Write file ID to meta file
 */
static inline int
writer_write_file_id(writer_context_t wctx)
{
  char file_name[128];
  FILE *fp;

  sprintf(file_name, "/mnt/meta_01/work_%02d.meta", wctx->disk_id + 1);
  if ((fp = fopen(file_name, "r+")) == NULL) {
    if ((fp = fopen(file_name, "w")) == NULL) {
      perror("fopen");
      return -1;
    }
  }

  fprintf(fp, "%d\n%d\n", wctx->file_id, wctx->old_file_id);
  fclose(fp);

  return 0;
}

/******************************************************************************
 * Function: writer_loop
 * - Write buffered packet data to the disk continuously
 */
static inline void
writer_loop(writer_context_t wctx)
{
  writer_buffer_t wbuf;
  int sig;
  int wbuf_id = 0;

  while (!done) {
    /* get a signal from engine */
    if (read(wctx->sockd[WRITER], &sig, sizeof(int)) <= 0) {
      perror("read");
      return;
    }

    /* end of the application */
    if (sig == -1)
      break;

    /* check the onwership of the current writer buffer */
    wbuf = &wctx->wbuf[wbuf_id];
    if (wbuf->owner != WRITER)
      continue;

    /* write the current writer buffer to the file */
    if (write(wctx->fd, wbuf->buf, wbuf->len) != wbuf->len) {
      perror("write");
      return;
    }
    wbuf->owner = ENGINE;
    wbuf->len   = 0;
    wctx->num_byte_writer += wbuf->len;
    wctx->num_byte_pcap   += wbuf->len;

    /* XXX: update writer log to SSD - how many data is written */

    /* update writer buffer ID for the next loop */
    wbuf_id = (wbuf_id + 1) % num_wbuf;

    /* close the file if it is full */
    if (sig == SIG_WRT_CLOSE) {
      close(wctx->fd);
      if ((wctx->fd = writer_open_pcap_file(wctx)) == -1) {
	perror("writer_open_pcap_file");
	return;
      }
      wctx->num_byte_pcap = 0;

      /* XXX: update writer log to SSD - what is the last file to write */

    }
  }

  while (1) {
    wbuf = &wctx->wbuf[wbuf_id];
    if (wbuf->len == 0)
      break;

    /* write the current writer buffer to the file */
    memset(wbuf->buf + wbuf->len, 0, size_wbuf - wbuf->len);
    wbuf->len = size_wbuf;
    if (write(wctx->fd, wbuf->buf, wbuf->len) != wbuf->len) {
      perror("write");
      return;
    }
    wbuf->len = 0;

    /* update writer buffer ID for the next loop */
    wbuf_id = (wbuf_id + 1) % num_wbuf;
  }

  close (wctx->fd);
}

/******************************************************************************
 * Function: writer_clear
 * - Clean-up function of a writer thread
 */
static inline void
writer_clear(writer_context_t wctx)
{
  int wbuf_id;

  for (wbuf_id = 0; wbuf_id < num_wbuf; wbuf_id++)
    free(wctx->wbuf[wbuf_id].buf);
}

/******************************************************************************
 * Function: writer_open_pcap_file
 * - Open a new pcap file to write packets
 */
static inline int
writer_open_pcap_file(writer_context_t wctx)
{
  int fd;
  char file_name[128];
  
  /* update the file ID */
  wctx->file_id++;

  /* set the name of the next pcap file to write */
  sprintf(file_name, "/mnt/work_%02d/dump_%05d.pcap", 
	  wctx->disk_id + 1, wctx->file_id);

  /* replace old file if there are no space to write any more */
  if (wctx->file_id >= NUM_PCAP_PER_DISK_MAX) {
    return -1;			/* disable old file overwriting when this disk is full */

    char old_file_name[128];
    sprintf(old_file_name, "/mnt/work_%02d/dump%05d.pcap",
	    wctx->disk_id + 1, wctx->old_file_id);
    if (rename(old_file_name, file_name) < 0) {
      perror("rename");
      return -1;
    }
    wctx->old_file_id++;
  }

  /* open the new pcap file */
  if ((fd = open(file_name, O_WRONLY | O_DIRECT | O_CREAT,
		 S_IRWXU | S_IRGRP | S_IROTH)) == -1) {
    perror("open");
    return -1;
  }

  if (writer_write_file_id(wctx) == -1) {
    perror("writer_write_file_id");
    return -1;
  }

  //printf("[WRITER-%02u] open a new pcap file: %s\n", wctx->disk_id, file_name);

  return fd;
}
