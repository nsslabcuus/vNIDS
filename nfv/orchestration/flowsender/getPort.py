#!/usr/bin/env python
# coding=utf-8
#------------------------------------------------------------------------------
# It's very important that the instance name is valid, otherwise the output 
# is undefined.
#------------------------------------------------------------------------------

import subprocess
import sys

if len(sys.argv) <= 1 :
    print("Usage: "+sys.argv[0]+" <instance name>"),
    print("e.g. : "+sys.argv[0]+" firewall_01 "),
    sys.exit(1)

instance=sys.argv[1]

# get port number
command="ovs-ofctl show ovs-lan|grep `xl list|grep '"+instance+"'|awk '{print $2}'`'\.0'|cut -d '(' -f1";
trafficPort=subprocess.check_output(command, shell=True);
command="ovs-ofctl show ovs-lan|grep `xl list|grep '"+instance+"'|awk '{print $2}'`'\.2'|cut -d '(' -f1";
messagePort=subprocess.check_output(command, shell=True);
print(trafficPort.rstrip().strip()+" "+messagePort.rstrip().strip()),


