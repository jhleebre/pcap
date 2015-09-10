#ifndef __ENGINE_H__
#define __ENGINE_H__

#include <stdint.h>
#include <pthread.h>

#include "main.h"
#include "writer.h"

struct engine_context;
typedef struct engine_context *engine_context_t;

struct engine_context {
  uint64_t num_byte;
  uint64_t num_pkt;
  writer_t wrt;
  unsigned lcore_id;
  pthread_mutex_t mutex;
};

int engine_main(void *dummy);

#endif
