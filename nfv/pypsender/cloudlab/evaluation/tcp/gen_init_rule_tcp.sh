#!/bin/bash
#------------------------------------------------------------------------------
#   This script generates rules, which will be initially installed in the source.
#   Some of these rules are dummy rules, and some are real rules. 
#   This script invokes ./gen_dummy_rule_udp.sh and ./gen_real_rule_udp.sh to 
#   achive this. 
#------------------------------------------------------------------------------

if [[ -z $3 ]]; then 
    echo "Usage: $0 <instance-id> <number of dummy rules> <number of real rules>"
    echo "E.g., $0 1 500 2"
    exit 1
fi

./gen_init_dummy_rule_tcp.sh $1 $2
./gen_init_real_rule_tcp.sh $1 $3

