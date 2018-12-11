#!/bin/bash
#-----------------------------------------------------------------------------------
#   This script is used to install rules into a VFW. 
#   These rules consist two type of rules: 
#       1) dummy rules -- must be generated prior by gen_dummy_rule_tcp.sh 
#       2) real rules -- must be generated prior by gen_rule_tcp.sh
#
#   The rule files are located in ../tcp/ 
#   files with X rules have file names ending with X.cfg 
#   E.g., rule_dummy_tcp_100.cfg contains 100 dummy TCP rules. 
#         rule_tcp_2.cfg contains 2 real TCP rules. 
#-----------------------------------------------------------------------------------

if [[ -z $3 ]]; then 
    echo "Usage: $0 <instance-id> <Number of dummy rules> <number of real rules>"
    echo "E.g., $0 1 0 2 --> means install 0 dummy rules and 2 real rules in instance '1'"
    exit 1
fi

python pymainsender.py file "../udp/init_rule_udp_dummy_"$1"_"$2".cfg" 1
python pymainsender.py file "../udp/init_rule_udp_real_"$1"_"$3".cfg" 1

