#!/bin/bash

for i in `seq -w 01 30`
do
    echo "disk"$i
    ./flowcnt ~/Desktop/result/$i/flow_len.out
done

