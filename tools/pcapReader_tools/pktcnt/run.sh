#!/bin/bash

for i in `seq -w 01 30`
do
    ./a.out ~/Desktop/result_at_22/pkt_len_$i.out > pkt_cnt_$i.out &
done

wait
