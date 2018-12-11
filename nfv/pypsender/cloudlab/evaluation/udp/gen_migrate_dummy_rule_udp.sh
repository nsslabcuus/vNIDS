#!/bin/bash
#-------------------------------------------------------------------------------------- 
#   This script generates dummy TCP rules which to be moved from source to dest. 
#   These dummy rules are a part of dummy rules that initially installed in the source.
#-------------------------------------------------------------------------------------- 

if [[ -z $1 ]]; then
    echo "Usage: $0 <number of dummy rules>"
    exit 1
fi

# These rules are a part of dummy rules. 
index=0
d1=136
d2=5
while [[ $index -lt $1 ]]; do 
    delta1=`expr $index / 250`
    delta2=`expr $index % 250`
    ip="10.130."$(expr $d1 + $delta1)"."$(expr $d2 + $delta2)
    echo "1,p_delete,"$ip"/32,10.130.127.2/32,1/65535,1/65535,tcp,allow,00:00:00:00:02:02"
    index=$(($index+1))
done

