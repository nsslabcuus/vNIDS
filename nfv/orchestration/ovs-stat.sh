#!/bin/bash
#------------------------------------------------------------------------------
# This script is used to dump flows within the ovs switch. 
# Usage: ./ovs-st.sh <key words> [is_descend?]
# The "key words" indicats which column to be sorted. 
#------------------------------------------------------------------------------

key_word=$1
order=$2
if [[ -z $key_word ]]; then 
    key_word="1"
fi
if [[ ! -z $order ]]; then 
    order="-r"
fi


if [[ $key_word == "duration" ]]; then 
    col="2"
elif [[ $key_word == "packets" ]]; then 
    col="3"
elif [[ $key_word == "bytes" ]]; then 
    col="4"
elif [[ $key_word == "idle" ]]; then 
    col="5"
else 
    echo "Usage: $0 <key_word> [is_descend?(input anything to sort descend)] "
    echo " Possible key words: "
    echo "|---------------------|"
    echo "|     duration        |"
    echo "|     packets         |"
    echo "|     bytes           |"
    echo "|     idle            |"
    echo "|---------------------|"
    exit 1
fi

watch -n 1 "ovs-ofctl dump-flows ovs-lan -O OpenFlow13 | awk -F ', ' '{\$1=\$3=\"\"; print \$0}' | sort -t '=' -k "$col" "$order" -n"


