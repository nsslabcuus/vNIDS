#!/bin/bash
#---------------------------------------------------------------------
# This script is used to migrate firewall instance. 
#
#---------------------------------------------------------------------
# Usage: ./migration.sh <Inst_src> <Inst_dst> 
# This means move all rules of Inst_src to Inst_dst. 
#
# e.g. : ./migration.sh 1 2 
# where '1' represents 'firewall_01', and '2' represents 'firewall_02'.
#---------------------------------------------------------------------

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <Inst_src> <Inst_dst> "
    echo "e.g $0 1 2"
    exit 1
fi

workdir="/local/work/clickos/nfv/orchestration/flowsender/"
Inst_src="firewall_0"$1
Inst_dst="firewall_0"$2
config_file=$workdir$Inst_dst".cfg"

ports=$(/local/work/clickos/nfv/orchestration/flowsender/getPort.py $Inst_dst)
traffic=$(echo $ports | cut -d ' ' -f 1)
traffic_mac="00:00:00:00:0$2"":00"
message=$(echo $ports | cut -d ' ' -f 2)
message_mac="00:00:00:00:0$2"":02"

# set traffic port
sed -i 's/pop_vlan,set_field=eth_dst->'$traffic_mac',output=.*\+/pop_vlan,set_field=eth_dst->'$traffic_mac',output='$traffic'"/' $config_file
# set message port
sed -i 's/set_field=eth_dst->'$message_mac',output=.*\+/set_field=eth_dst->'$message_mac',output='$message'"/' $config_file

# invoke setup_back_bone.py to push flow entries.
/local/work/clickos/nfv/orchestration/flowsender/setup_back_bone.py $config_file 127.0.0.1 

