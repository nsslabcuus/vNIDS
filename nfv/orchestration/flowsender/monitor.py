#!/usr/bin/env python
# coding=utf-8

import subprocess
import sys
import time

if len(sys.argv) <= 2 :
    print("Usage: "+sys.argv[0]+" <instance name> <incoming port>"),
    print("e.g. : "+sys.argv[0]+" firewall_01 1 --> traffic from ovs-lan, 1 port and to firewall_01"),
    sys.exit(1)

commands="./getPort.py "+sys.argv[1]+" | cut -d ' ' -f 1"
trafficPort=subprocess.check_output(commands, shell=True) 
flow1 = "out_port=" + trafficPort.strip('\n').strip(' ')
command1 = "ovs-ofctl dump-flows ovs-lan "+flow1+" | awk -F '=' '{if(NR>1){print $5\",\"$6}}' | awk -F ',' 'BEGIN{p=0;r=0}{p+=$1;r+=$3}END{print p\",\"r}'"

flow2 = "dl_src=00:00:00:00:01:00"
command2 = "ovs-ofctl dump-flows ovs-lan "+flow2+" | awk -F '=' '{if(NR>1){print $5\",\"$6}}' | awk -F ',' 'BEGIN{p=0;r=0}{p+=$1;r+=$3}END{print p\",\"r}'"

rate = subprocess.check_output(command1, shell=True)
timeBegin1 = time.time()
r_data = rate.strip('\n').strip(' ').split(',') 
r_pre_packets=float(r_data[0])
r_pre_bytes=float(r_data[1])

thru = subprocess.check_output(command2, shell=True)
timeBegin2 = time.time()
t_data = thru.strip('\n').strip(' ').split(',') 
t_pre_packets=float(t_data[0])
t_pre_bytes=float(t_data[1])


while 1:
    timeEnd1 = time.time()
    d_time1 = timeEnd1 - timeBegin1
    rate = subprocess.check_output(command1, shell=True)
    timeBegin1 = time.time()

    timeEnd2 = time.time()
    d_time2 = timeEnd2 - timeBegin2
    thru = subprocess.check_output(command2, shell=True)
    timeBegin2 = time.time()

    r_data = rate.strip('\n').strip(' ').split(',') 
    r_packets = float(r_data[0])
    r_bytes = float(r_data[1])
    r_d_packets = (r_packets - r_pre_packets) / d_time1
    r_d_bytes = (r_bytes - r_pre_bytes) * 8 / d_time1
    r_pre_packets = r_packets
    r_pre_bytes = r_bytes

    t_data = thru.strip('\n').strip(' ').split(',') 
    t_packets = float(t_data[0])
    t_bytes = float(t_data[1])
    t_d_packets = (t_packets - t_pre_packets) / d_time2
    t_d_bytes = (t_bytes - t_pre_bytes) * 8 / d_time2
    t_pre_packets = t_packets
    t_pre_bytes = t_bytes

    print str(r_d_packets) + "," + str(r_d_bytes) + "," + str(t_d_packets) + "," + str(t_d_bytes) + "," + str(r_d_packets - t_d_packets) + "," + str(r_d_bytes - t_d_bytes)
    time.sleep(2) 








