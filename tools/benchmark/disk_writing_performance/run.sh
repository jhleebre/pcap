#!/bin/bash

rm -rf ./results/*

for t in fwrite direct
do
    for ((i = 1024; i <= 2097152; i *= 2))
    do
	echo "=============================================="
	echo "start ./test "$t" "$i
	dump_out=`echo "./results/"$t"-"$i"-dump.txt"`
	iostat_out=`echo "./results/"$t"-"$i"-iostat.txt"`
	sudo ./test $t $i > $dump_out &
	iostat -mx 1 > $iostat_out &
	sleep 120
	sudo killall -SIGTERM -w -v iostat
	sudo killall -SIGINT -w -v test
    done
done

echo "=============================================="
ls -al ./results/*
echo "=============================================="

exit 0
