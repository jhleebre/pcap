#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef __USE_FILE_OFFSET64
#define __USE_FILE_OFFSET64
#endif
/*****************************************************************************/
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <assert.h>
/*****************************************************************************/
#define NUM_DISK 30
typedef enum{FWRITE, DIRECT} IO_TYPE;
/*****************************************************************************/
struct writer_context {
  int id;
  int size;
  uint64_t bytes;
  bool done;
};
/*****************************************************************************/
bool done;
pthread_t writer[NUM_DISK];
struct writer_context wctx[NUM_DISK];
/*****************************************************************************/
void print_usage(char *arg);
void *fwrite_main(void *arg);
void *direct_main(void *arg);
void interrupt_handler(int signal);
double get_time_diff_sec(struct timeval t1, struct timeval t2);
/*****************************************************************************/
int
main(int argc, char *argv[])
{
  IO_TYPE ioType;
  size_t size;
  int i;
  int wrtCnt = 0;
  struct timeval curT, prvT, iniT;
  uint64_t curB, prvB = 0;
  double elapsed;
  
  /* check & parse input arguments */
  if (argc != 3)
    goto main_error;

  if (strcmp(argv[1], "fwrite") == 0)
    ioType = FWRITE;
  else if (strcmp (argv[1], "direct") == 0)
    ioType = DIRECT;
  else
    goto main_error;

  size = atoi(argv[2]);
  if (size == 0 || size % 512 != 0)
    goto main_error;

  if (signal(SIGINT, interrupt_handler) == SIG_ERR) {
    perror("signal");
    return 0;
  }

  done = false;

  /* create child threads */
  for (i = 0; i < NUM_DISK; i++) {
    wctx[i].id = i + 1;
    wctx[i].size = size;
    wctx[i].bytes = 0;
    wctx[i].done = false;
    if (pthread_create(&writer[i], NULL,
		       ioType == FWRITE ? fwrite_main : direct_main,
		       (void *)&wctx[i])) {
      perror("pthread_create");
      return 1;
    }
    wrtCnt++;
  }

  /* print status */
  gettimeofday(&iniT, NULL);
  prvT = iniT;

  while (!done) {
    gettimeofday(&curT, NULL);
    if ((elapsed = get_time_diff_sec(curT, prvT)) >= 1) {
      curB = 0;
      for (i = 0; i < wrtCnt; i++)
	curB += wctx[i].bytes;
      printf("%2.2f GBps\t", (curB - prvB)/elapsed * 1e-9);
      printf("%2.2f Gbps\t", 8 * (curB - prvB)/elapsed * 1e-9);

      elapsed = get_time_diff_sec(curT, iniT);
      printf("%2.2f GBps\t", curB/elapsed * 1e-9);
      printf("%2.2f Gbps\n", 8 * curB/elapsed * 1e-9);

      //printf("%llu B\n", curB);
      prvB = curB;
      prvT = curT;
    }
    sleep(1);    
  }

  /* wait until the end of every child */
  for (i = 0; i < wrtCnt; i++)
    pthread_join(writer[i], NULL);

  fprintf(stderr, "main - all children are dead\n");
  
  return 0;

 main_error:
  print_usage(argv[0]);
  return 0;
}
/*****************************************************************************/
void
print_usage(char *arg)
{
  fprintf(stderr, "USAGE   : %s [I/O TYPE] [SIZE]\n", arg);
  fprintf(stderr, "I/O TYPE: fwrite / direct\n");
  fprintf(stderr, "SIZE    : multiple of 512\n");
}
/*****************************************************************************/
void *
fwrite_main(void *arg)
{
  struct writer_context *wctxp = (struct writer_context *)arg;
  char outfile[32];
  FILE *fp;
  char *buf;
  int res;

  sprintf(outfile, "/mnt/work_%02d/dump.txt", wctxp->id);
  if (posix_memalign((void**)&buf, 512, wctxp->size)) {
    perror("posix_memalign");
    goto fwrite_main_end_1;
  }

  memset(buf, 'a', wctxp->size);

  if ((fp = fopen(outfile, "w")) == NULL) {
    perror("fopen");
    goto fwrite_main_end_2;
  }

  while (!wctxp->done) {
    if ((res = fwrite(buf, 1, wctxp->size, fp)) <= 0) {
      if (errno == EAGAIN || errno == EINTR) 
	continue;
      perror("fwrite");
      break;
    }
    wctxp->bytes += res;
  }

  fclose(fp);
  
  fprintf(stderr, "fwrite_main %d - I'm dying\n", wctxp->id);

 fwrite_main_end_2:
  free(buf);
 fwrite_main_end_1:
  pthread_exit(NULL);
}
/*****************************************************************************/
void *
direct_main(void *arg)
{
  struct writer_context *wctxp = (struct writer_context *)arg;
  char outfile[32];
  int fd;
  char *buf;
  int res;

  sprintf(outfile, "/mnt/work_%02d/dump.txt", wctxp->id);
  if (posix_memalign((void**)&buf, 512, wctxp->size)) {
    perror("posix_memalign");
    goto direct_main_end_1;
  }

  memset(buf, 'a', wctxp->size);

  if ((fd = open(outfile, O_WRONLY | O_CREAT | O_DIRECT,
		 S_IRWXU | S_IRGRP | S_IROTH)) == -1) {
    perror("open");
    goto direct_main_end_2;
  }

  while (!wctxp->done) {
    if ((res = write(fd, buf, wctxp->size)) <= 0) {
      if (errno == EAGAIN || errno == EINTR) 
	continue;
      perror("write");
      break;
    }
    wctxp->bytes+= res;
  }

  fprintf(stderr, "direct_main %d - I'm dying\n", wctxp->id);

  close(fd);
 direct_main_end_2:
  free(buf);
 direct_main_end_1:
  pthread_exit(NULL);
}
/*****************************************************************************/
double
get_time_diff_sec(struct timeval t1, struct timeval t2)
{
  return (t1.tv_sec - t2.tv_sec + (t1.tv_usec - t2.tv_usec) * 1e-6);
}
/*****************************************************************************/
void 
interrupt_handler(int signal)
{
  int i;

  assert(signal == SIGINT);
  
  for (i = 0; i < NUM_DISK; i++) {
    if (writer[i] == pthread_self()) {
      wctx[i].done = true;
      return;
    }
  }

  done = true;

  for (i = 0; i < NUM_DISK; i++) {
    pthread_kill(writer[i], signal);
  }
}
