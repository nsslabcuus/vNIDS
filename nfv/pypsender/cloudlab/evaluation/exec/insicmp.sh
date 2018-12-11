#!/bin/bash
#-----------------------------------------------------------------------------------
#   This script is used to install rules into a VFW. 
#   Typically, install ICMP rules into the firewall, if you pass a rule spec file 
#   containing ICMP rules. 
#-----------------------------------------------------------------------------------

if [[ -z $1 ]]; then
    echo "Usage: $0 <rule.cfg>"
    echo "E.g., $0 ../icmp/rule_icmp.cfg"
    exit 1
fi

# send rules to the firewall 
python pymainsender.py file $1 1

