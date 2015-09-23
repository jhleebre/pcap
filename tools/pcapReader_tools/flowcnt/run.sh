#!/bin/bash

for min in `seq -w 0 59`
do
    total=0
    for i in `seq -w 01 30`
    do
	cnt=`./flowcnt 22 $min 0 ~/Desktop/result_at_22/flow_len_$i.out`
	let "total = total + cnt"
    done
    echo "22:"$min":00 "$total
done

