#!/bin/bash

for i in `seq -w 01 02`
do
    echo "umount -v -l /mnt/meta_"$i
    umount -v -l /mnt/meta_$i
done

for i in `seq -w 01 30`
do
    echo "umount -v -l /mnt/work_"$i
    umount -v -l /mnt/work_$i
done

