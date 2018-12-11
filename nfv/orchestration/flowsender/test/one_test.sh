#!/bin/bash

if [[ -z $1 ]]; then 
    echo "Usage: $0 <file> [IP address] "
    echo "E.g., $0 150.cfg 10.130.127.4"
    exit 1
fi

IP=$2
if [[ -z $IP ]]; then
    IP="127.0.0.1"
fi

old=`date +%s.%N`
./setup_back_bone.py $1 $IP > /dev/null 2>&1
new=`date +%s.%N`

#echo "old: $old"
#echo "new: $new"
old_sec=`echo $old | cut -d '.' -f1`
old_nsec=`echo $old | cut -d '.' -f2`
new_sec=`echo $new | cut -d '.' -f1`
new_nsec=`echo $new | cut -d '.' -f2`

#echo $old_sec"."$old_nsec
#echo $new_sec"."$new_nsec

dms_sec=`expr $(expr $new_sec \* 1000) - $(expr $old_sec \* 1000)`
dms_nsec=`expr $(expr $new_nsec / 1000000) - $(expr $old_nsec / 1000000)`
del=`expr $dms_sec + $dms_nsec`
echo $del 

