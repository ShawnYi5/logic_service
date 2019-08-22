#!/bin/ksh
#Create a single primary partiton with whole disk size and create LVM PV on it
disk=$1
partno=1
parted_label=$2

if [[ -z $disk ]]; then
echo "Usage: $0 disk device name: e.g $0 /dev/sdb"
exit
fi

parted $disk <<ESXU
mklabel gpt
mkpart $parted_label xfs 0 -1
ignore
quit
ESXU
