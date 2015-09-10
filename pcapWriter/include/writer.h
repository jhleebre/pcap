#ifndef __WRITER_H__
#define __WRITER_H__

#include <pthread.h>

#include "engine.h"

struct writer;
typedef struct writer *writer_t;
struct writer_context;
typedef struct writer_context *writer_context_t;
struct writer_buffer;
typedef struct writer_buffer *writer_buffer_t;

struct writer {
  pthread_t thread;
  int sockd[2];
  int cpu;
  struct writer_context *wctx;
  struct engine_context *ectx;
  unsigned disk_id;
};

struct writer_context {
  int sockd[2];
  unsigned disk_id;
  int file_id;
  int old_file_id;
  int fd;
  writer_buffer_t wbuf;
  writer_buffer_t wbuf_ptr;
  int wbuf_id;
  uint64_t num_byte_engine;
  uint64_t num_byte_writer;
  uint64_t num_byte_pcap;
};

struct writer_buffer {
  uint32_t len;
  int owner;
  unsigned char *buf;  
};

void *writer_main(void *arg);

#endif
