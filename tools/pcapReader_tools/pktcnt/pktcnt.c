#include <stdio.h>
#include <stdint.h>

int
main(int argc, char *argv[])
{
  uint64_t cnt[1600] = {0};
  int h, m, s, us, bytes, i;
  FILE *fp = fopen(argv[1], "r");
  
  if (fp == NULL)
    return 0;

  while (!feof(fp)) {
    fscanf(fp, "%d %d %d %d %d\n", &h, &m, &s, &us, &bytes);
    cnt[bytes]++;
  }

  fclose(fp);

  for (i = 0; i < 1600; i++) {
    printf("%d %llu\n", i, cnt[i]);
  }

  return 0;  
}
