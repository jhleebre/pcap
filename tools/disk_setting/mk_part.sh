#!/bin/bash

DISK='
/dev/sda
/dev/sdb
/dev/sdc
/dev/sdd
/dev/sde
/dev/sdf
/dev/sdg
/dev/sdh
/dev/sdi
/dev/sdj
/dev/sdk
/dev/sdl
/dev/sdm
/dev/sdn
/dev/sdo
/dev/sdp
/dev/sdq
/dev/sdr
/dev/sds
/dev/sdt
/dev/sdu
/dev/sdv
/dev/sdw
/dev/sdx
/dev/sdy
/dev/sdz
/dev/sdaa
/dev/sdab
/dev/sdac
/dev/sdad
/dev/sdae
/dev/sdaf
'

for d in $DISK
do
    parted $d --script -- mklabel gpt
    parted $d --script -- mkpart ext4 1MB -1
done