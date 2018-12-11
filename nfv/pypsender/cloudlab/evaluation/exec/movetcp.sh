#!/bin/bash
#-----------------------------------------------------------------------------
#   This script starts a migraion: 
#       First, send p_append to dst instance. 
#       Second, send p_delete to source instance. 
#       Third, send p_delete_end to source instance. 
#-----------------------------------------------------------------------------
if [[ -z $2 ]]; then 
    echo "Usage: $0 <number of dummy rules to move> <number of real rules to move>"
    exit 1
fi

python pymainsender.py file ../etc/migrate_p_append.cfg 1
python pymainsender.py file "../tcp/migrate_rule_tcp_"$1"_"$2".cfg" 1
python pymainsender.py file ../etc/migrate_p_delete_end.cfg 1

