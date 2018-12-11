#!/bin/bash

if [[ -z $1 ]]; then 
    echo "Usage: $0 <rum_times> [controller IP] "
    echo "E.g., $0 100 127.0.0.1  --> run 100 times for each tests."
    exit 1
fi

time=$1
IP=$2
files=$(ls *.cfg)
echo $files
for f in $files; do 
    ./run_test.sh $f $time $IP
    echo "$f Completed!"
done
echo ""
echo "+------------------------------+"
./parse_result.sh
echo "+------------------------------+"

