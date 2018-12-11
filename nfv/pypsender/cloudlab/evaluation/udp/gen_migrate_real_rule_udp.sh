#!/bin/bash
#------------------------------------------------------------------------------------
#   This script generates real rules, which will be moved from the source. 
#   These real rules are a part of real rules that are initially installed in the source. 
#------------------------------------------------------------------------------------

if [[ -z $1 ]]; then
    echo "Usage: $0 <number of real rules>"
    exit 1
fi

# Simplify. 

count=$(expr $1 / 2)
index=0
while [[ $index -lt $count ]]; do 
    index=$(($index+1))
    # Allow client to server. 
    echo "1,p_delete,10.130.127."$index"1/32,10.130.127.2/32,1/65535,1/65535,udp,allow,00:00:00:00:02:02"
    # Allow server to client.
    echo "1,p_delete,10.130.127.2/32,10.130.127."$index"1/32,1/65535,1/65535,udp,allow,00:00:00:00:02:02"
done


