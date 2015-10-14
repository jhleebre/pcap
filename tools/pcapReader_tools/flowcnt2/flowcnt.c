#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

unsigned long long cnt[24][60] = {0};

static inline void
print_usage(char *app)
{
  fprintf(stderr, "usage: %s [FILE]\n", app);
}

int
main(int argc, char *argv[])
{
  unsigned long long h, m, s = 0, us = 0;
  FILE *fp;

  if (argc != 2) {
    print_usage(argv[0]);
    return 0;
  }

  fp = fopen(argv[1], "r");
  if (fp == NULL) {
    fprintf(stderr, "cannot open the file: %s\n", argv[4]);
    return 0;
  }

  while (!feof(fp)) {
    int sh, sm, ss, sus, eh, em, es, eus, duration, bytes;
    if (fscanf(fp, "%d %d %d %d %d %d %d %d %d %d\n",
	       &sh, &sm, &ss, &sus, &eh, &em, &es, &eus, &duration, &bytes) != 10) {
      perror("fscanf");
      assert(0);
    }

    if (sh != 22)
      continue;

    if (sh < 15)
      sh += 24;
    if (eh < 15)
      eh += 24;
    
    unsigned long long st = (((((unsigned long long)sh * 60) + (unsigned long long)sm) * 60) + (unsigned long long)ss) * 1000000 +
      (unsigned long long)sus;
    unsigned long long et = (((((unsigned long long)eh * 60) + (unsigned long long)em) * 60) + (unsigned long long)es) * 1000000 +
      (unsigned long long)eus;
    
    if (st > et) {
      fprintf(stderr, "%2d:%2d:%2d:%6d ~ %2d:%2d:%2d:%6d ==> %llu ~ %llu\n", sh, sm, ss, sus, eh, em, es, eus, st, et);
      assert(0);
    }

    for (h = 18; h < 38; h++) {
      for (m = 0; m < 60; m++) {
	unsigned long long t  = ((((h * 60) + m) * 60) + s) * 1000000 + us;
	if (st <= t && t <= et)
	  cnt[h-18][m]++;
      }
    }
  }

  for (h = 18; h < 38; h++) {
    for (m = 0; m < 60; m++) {
      printf("%llu %llu %llu\n", h < 24 ? h : h - 24, m, cnt[h-18][m]);
    }
  }

  fclose(fp);

  return 0;
}
