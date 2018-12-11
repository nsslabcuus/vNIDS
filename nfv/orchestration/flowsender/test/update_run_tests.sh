#!/bin/bash

if [[ -z $3 ]]; then 
    echo "Usage: $0 <rum_times> <start> <end>"
    echo "E.g., $0 100 1 50  --> run 100 times for each tests. No. of rules: 1, 51, 101, ..., end"
    exit 1
fi

time=$1
s=$2
end=$3
index=$s
while [[ ! $index -gt  $end ]]; do
    index=$(($index+10))
    ./update_one_test.sh $index $time
    echo "$f Completed!"
done
echo ""
echo "+------------------------------+"
./parse_result.sh
echo "+------------------------------+"

