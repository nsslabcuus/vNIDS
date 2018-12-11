#!/bin/bash 
#------------------------------------------------------------------------------
#   Install a number of dummy rules. Those rules will never be mached during
#   the experiment. 
#------------------------------------------------------------------------------

if [[ -z $2 ]]; then 
    echo "Usage: $0 <rule number> <t|u|i>"
    echo "E.g., $0 1000 u --> append 1000 rules at the end of the table. For UDP test."
    exit 1
fi

repeat=`expr $1 / 20`
if [[ "$2" == 't' ]]; then
    ./pytester.py file rule_dummy_tcp.cfg $repeat
elif [[ "$2" == 'u' ]]; then 
    ./pytester.py file rule_dummy_udp.cfg $repeat
elif [[ "$2" == 'i' ]]; then 
    ./pytester.py file rule_dummy_icmp.cfg $repeat
else
    echo "Usage: $0 <rule number> <t|u|i>"
    echo "E.g., $0 1000 u --> append 1000 rules at the end of the table. For UDP test."
    exit 1
fi

