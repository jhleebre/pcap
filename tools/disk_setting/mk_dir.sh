#!/bin/bash

for i in `seq -w 01 30`
do
    mkdir /mnt/work_$i
done

for i in `seq -w 01 02`
do
    mkdir /mnt/meta_$i
done
