#!/bin/bash
#------------------------------------------------------------------------------------
#   This script generates real rules, which will be initially installed in the source. 
#   The real rules are potentially matched in the experiment. 
#------------------------------------------------------------------------------------

if [[ -z $2 ]]; then
    echo "Usage: $0 <instance-id> <number of real rules>"
    exit 1
fi

count=$(expr $2 / 2)
index=0 

while [[ $index -lt $count ]]; do 
    index=$(($index+1))
    # Allow client to server. 
    echo $1",append,10.130.127."$index"1/32,10.130.127.2/32,1/65535,1/65535,udp,allow"
    # Allow server to client.
    echo $1",append,10.130.127.2/32,10.130.127."$index"1/32,1/65535,1/65535,udp,allow"
done


