#!/bin/bash

HOURS='18 19 20 21 22 23 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14'
MINS='0 30'

for h in $HOURS
do
    for m in $MINS
    do

	total=0
	for i in `seq -w 01 30`
	do
	    cnt=`./flowcnt $h $m 0 ~/Desktop/result/$i/flow_len.out`
	    let "total = total + cnt"
	done
	echo $h":"$m":00 "$total

    done
done

exit
