#!/bin/bash

if [[ -z $1 ]]; then 
    echo "Usage: $0 <No. of rules> [repeat]"
    echo "E.g., $0 10 100 --> 10 rules, run 100 times and conpute the average"
    exit 1
fi

count=$1
repeat=$2
if [[ -z $repeat ]]; then
    repeat=10 
fi

rm -rf $count"_update_sw.time.dat" > /dev/null 2>&1
index=0
while [[ $index -lt $repeat ]]; do 
    let "index=$index+1";
    time=`./update_test.sh $count`
    sleep 0.2
    ./clear_flows.py > /dev/null 2>&1;
    echo $time >> $count"_update_sw.time.dat"
    sleep 0.2
done

