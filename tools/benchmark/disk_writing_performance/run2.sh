#!/bin/bash

for ((i = 1024; i <= 2097152; i *= 2))
do
    echo "=============================================="
    echo "start ./test direct "$i
    sudo ./test direct $i &
    sleep 60
    sudo killall -SIGINT -w -v test
done

exit 0
