#!/bin/bash

for i in `seq -w 01 02`
do
    sudo mount -v -t ext4 -L META_$i /mnt/meta_$i
done

for i in `seq -w 01 30`
do
    sudo mount -v -t ext4 -L WORK_$i /mnt/work_$i
done
