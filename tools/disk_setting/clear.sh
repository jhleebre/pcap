#!/bin/bash

for i in `seq -w 01 30`
do
    rm -rvf /mnt/work_$i/*
done

for i in `seq -w 01 02`
do
    rm -rvf /mnt/meta_$i/*
done