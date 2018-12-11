#!/bin/bash 
#------------------------------------------------------------------------------
#   This script generates a number of dummy TCP rules. 
#   This number of dummy rules will never been matched during the experiment. 
#   However, some of them are to be moved between VFW instances. 
#------------------------------------------------------------------------------

if [[ -z $2 ]]; then
    echo "Usage: $0 <instance-id> <number of dummy rules>"
    exit 1
fi 

index=0
d1=136
d2=5
while [[ $index -lt $2 ]]; do 
    delta1=`expr $index / 250`
    delta2=`expr $index % 250`
    ip="10.130."$(expr $d1 + $delta1)"."$(expr $d2 + $delta2)
    echo $1",append,"$ip"/32,10.130.127.2/32,1/65535,1/65535,udp,allow"
    index=$(($index+1))
done 


