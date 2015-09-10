#!/bin/bash

FILESIZE=1073741824

function create {
	echo "Setting Disk: "$1

	for j in `seq -w 0 99999`
	do
		SPACE=`df -B 1 | grep "mnt/work_"$1 | sed -e 's/\/dev\/[^\ ]*\ *[0-9]*\ *[0-9]*\ *//' -e 's/\ *[0-9]*%.*//'`	
		if (( "$SPACE" >= "$FILESIZE" ))
		then
			touch /mnt/work_$1/dump_$j.fcap
			fallocate -l 1g /mnt/work_$1/dump_$j.fcap
			#echo "Disk["$1"]: Dumpfile["$j"] is created"
		else
			break
		fi
	done
}

for i in `seq -w 01 30`
do
	create $i
done
wait

exit 0
