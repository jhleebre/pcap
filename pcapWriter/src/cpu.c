#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/******************************************************************************
 * Header files
 */
#include <unistd.h>
#include <errno.h>
#include <numa.h>
#include <sched.h>
#include <sys/stat.h>
#include <assert.h>

#include "cpu.h"

/******************************************************************************
 * Function: bind_cpu
 * - Pin the current thread to CPU core.
 * - Bind memory allocation to the NUMA node
 */
int
bind_cpu(int cpu)
{
  cpu_set_t *cmask;
  struct bitmask *bmask;
  size_t num_cpu;
  int ret;

  /* check the validity of the input argument */
  num_cpu = sysconf(_SC_NPROCESSORS_ONLN);
  if (cpu < 0 || cpu >= (int)num_cpu) {
    errno = -EINVAL;
    return -1;
  }

  /* set CPU affinity */
  cmask = CPU_ALLOC(num_cpu);
  if (cmask == NULL)
    return -1;
  CPU_ZERO_S(num_cpu, cmask);
  CPU_SET_S(cpu, num_cpu, cmask);
  ret = sched_setaffinity(0, num_cpu, cmask);
  CPU_FREE(cmask);

  /* set memory allocation mask */
  if (numa_max_node() == 0)
    return ret;
  bmask = numa_bitmask_alloc(16);
  assert(bmask);
  //numa_bitmask_setbit(bmask, cpu < 8 ? 0 : 1);
  numa_bitmask_setbit(bmask, cpu & 1);
  numa_set_membind(bmask);
  numa_bitmask_free(bmask);

  return ret;
}
