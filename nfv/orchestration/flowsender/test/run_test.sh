#!/bin/bash

if [[ -z $1 ]]; then 
    echo "Usage: $0 <file name> [count] [contorller IP]"
    echo "E.g., $0 150.cfg 100 127.0.0.1 --> run 100 times and conpute the average"
    exit 1
fi
count=$2
if [[ -z $count ]]; then
    count=10 
fi
IP=$3

fname=`echo $1 | cut -d '.' -f1`
rm -rf $fname"_update_sw.time.dat" > /dev/null 2>&1
index=0
while [[ $index -lt $count ]]; do 
    let "index=$index+1";
    time=`./one_test.sh $1 $IP`;
    sleep 0.5
    ./clear_flows.py > /dev/null 2>&1;
    echo $time >> $fname"_update_sw.time.dat"
done

