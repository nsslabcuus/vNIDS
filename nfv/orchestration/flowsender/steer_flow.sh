#!/bin/bash



ports=$(./getPort.py firewall_01)

traffic=$(echo $ports | cut -d ' ' -f 1)
message=$(echo $ports | cut -d ' ' -f 2)

# set traffic port
sed -i 's/pop_vlan,output=.*\+/pop_vlan,output='$traffic',/' firewall_01.cfg 
# set message port
sed -i 's/set_field=eth_dst->00:00:00:00:01:02,output=.*\+/set_field=eth_dst->00:00:00:00:01:02,output='$message'",/' firewall_01.cfg

# invoke setup_back_bone.py to push flow entries.
./setup_back_bone.py 



