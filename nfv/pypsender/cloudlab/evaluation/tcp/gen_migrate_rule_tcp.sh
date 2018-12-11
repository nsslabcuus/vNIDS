#!/bin/bash
#------------------------------------------------------------------------------
#   This script generates rules, which will be moved from the source to the dst. 
#   Some of these rules are dummy rules, and some are real rules. 
#------------------------------------------------------------------------------

if [[ -z $2 ]]; then 
    echo "Usage: $0 <number of dummy rules> <number of real rules>"
    exit 1
fi

./gen_migrate_dummy_rule_tcp.sh $1
./gen_migrate_real_rule_tcp.sh $2

