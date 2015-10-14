#!/bin/bash

rm *.out *.sort.uniq *.dist

for i in `seq -w 01 30`
do
    cp ~/Desktop/result_at_22_new/$i/flow_len.out flow_len_$i.out
    awk '{print $9}' flow_len_$i.out > duration_$i.out
    sort -rg duration_$i.out | uniq -c > duration_$i.dist
done


