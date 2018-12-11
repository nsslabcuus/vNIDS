#!/bin/bash

if [[ -z $1 ]]; then 
    echo "Uasge: $0 <No. of rules>"
    exit 1
fi 

index=0
old=`date +%s.%N`
while [[ $index -lt $1 ]]; do 
    ovs-ofctl add-flow ovs-lan "dl_type=0x0800,nw_dst=10.130.127.11,priority=65500,actions=pop_vlan,set_field:00:00:00:00:01:00->eth_dst,output=9"
    index=$(($index+1))
done 
new=`date +%s.%N`

old_sec=`echo $old | cut -d '.' -f1`
old_nsec=`echo $old | cut -d '.' -f2`
new_sec=`echo $new | cut -d '.' -f1`
new_nsec=`echo $new | cut -d '.' -f2`
dms_sec=`expr $(expr $new_sec \* 1000) - $(expr $old_sec \* 1000)`
dms_nsec=`expr $(expr $new_nsec / 1000000) - $(expr $old_nsec / 1000000)`
echo $1","`expr $dms_sec + $dms_nsec`

ovs-ofctl del-flows ovs-lan
