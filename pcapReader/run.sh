#!/bin/bash

# TARGET HOURES TO ANALYZE
TIME=21

# SET INPUT FILES
rm -rf input
mkdir input

cd ./input
for i in `seq -w 01 30`
do
    rm -rf $i
    mkdir $i
done

for i in `seq -w 01 30`
do
    cd ./$i
    FILE=`ls -al /mnt/work_$i/*.pcap | grep "\s$TIME:" | sed -e 's/.*\/mnt/\/mnt/'`
    for j in $FILE
    do
	ln -s $j
    done
    cd ..
done
cd ..

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
    #./pcapReader $FILE > disk_$i.out &
done

wait
