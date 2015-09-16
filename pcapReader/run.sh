#!/bin/bash
FILES=`ls /mnt/work_01/10min/*.pcap`

./pcapReader $FILES
