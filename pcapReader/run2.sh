#!/bin/bash

# CLEAN-UP OUTPUT DIRECTORIES
rm -rf result
mkdir result
for i in `seq -w 01 30`
do
    mkdir result/$i
done

# CREATE OUTPUT
for i in `seq -w 01 30`
do
    cp ~/pcap/pcapReader/pcapReader ~/pcap/pcapReader/result/$i
    cd ~/pcap/pcapReader/result/$i
    FILE=`ls /mnt/work_$i/*.pcap`
    ./pcapReader $FILE > disk_$i.out &
done

wait
