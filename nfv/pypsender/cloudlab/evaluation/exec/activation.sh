#!/bin/bash
#------------------------------------------------------------------------------
#   Activate/deactivate firewall instances.
#------------------------------------------------------------------------------

if [[ -z $1 ]]; then 
    echo "Usage: $0 <instance-id>"
    echo "e.g. $0 1"
    exit 1
fi

python pymainsender.py notify $1

