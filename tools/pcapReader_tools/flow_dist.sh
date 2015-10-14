#!/bin/bash

rm *.out *.sort.uniq *.disk

for i in `seq -w 01 30`
do
    cp ~/Desktop/result_at_22_new/$i/flow_len.out flow_len_$i.out
    awk '{print $9}' flow_len_$i.out > duration_$i.out
    sort -rgu duration_$i.out > duration_$i.sort.uniq

    while read line
    do
	cnt=`grep $line duration_$i.out | wc -l`
	echo -n $line" "$cnt >> duration_$i.dist
	echo >> duration_$i.dist
    done < duration_$i.sort.uniq
done


