#ifndef __MACRO_H__
#define __MACRO_H__

#ifndef gbps
#define gbps(bytes, secs) ((double)((bytes) * 8 / 1e9 / (secs)))
#endif

#ifndef mpps
#define mpps(pkts, secs) ((double)((pkts) / 1e6 / (secs)))
#endif

#ifndef is_power_of_2
#define is_power_of_2(x) (((x) & ((x) - 1)) == 0)
#endif

#ifndef is_multiple_of_512
#define is_multiple_of_512(x) ((x) % 512 == 0)
#endif

#endif
