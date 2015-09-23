#include <stdio.h>
#include <stdlib.h>

static inline void
print_usage(char *app)
{
  fprintf(stderr, "usage: %s [HOUR] [MIN] [SEC] [FILE]\n", app);
}

int
main(int argc, char *argv[])
{
  int h, m, s, cnt = 0;
  FILE *fp;

  if (argc != 5) {
    print_usage(argv[0]);
    return 0;
  }

  h = atoi(argv[1]);
  if (h < 0 || h > 23) {
    fprintf(stderr, "invalid argument (1): %s\n", argv[1]);
    print_usage(argv[0]);
    return 0;
  }

  m = atoi(argv[2]);
  if (m < 0 || m > 59) {
    fprintf(stderr, "invalid argument (2): %s\n", argv[2]);
    print_usage(argv[0]);
    return 0;
  }

  s = atoi(argv[3]);
  if (s < 0 || s > 59) {
    fprintf(stderr, "invalid argument (3): %s\n", argv[3]);
    print_usage(argv[0]);
    return 0;
  }

  fp = fopen(argv[4], "r");
  if (fp == NULL) {
    fprintf(stderr, "cannot open the file: %s\n", argv[4]);
    return 0;
  }

  while (!feof(fp)) {
    int sh, sm, ss, sus, eh, em, es, eus, duration, bytes;
    fscanf(fp, "%d %d %d %d %d %d %d %d %d %d\n",
	   &sh, &sm, &ss, &sus, &eh, &em, &es, &eus, &duration, &bytes);
    if (sh <= h && h <= eh &&
	sm <= m && m <= em &&
	ss <= s && s <= es)
      cnt++;
  }

  printf("%d\n", cnt);

  fclose(fp);

  return 0;
}
