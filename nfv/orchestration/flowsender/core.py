#!/usr/bin/env python
# coding=utf-8

__author__ = 'Zhizhong Pan'

import time
import argparse
import subprocess
import json
import sys

# ip        :   string 
# port_no   :   dictionary, port -> in_out
def get_throughput(ip, port_no, switch_id):
    command = "curl http://" + ip + ":8080/wm/core/switch/" + switch_id + "/port/json 2>/dev/null"
    p = subprocess.check_output(command, shell=True);
    all_data = json.loads(p);
    port_data = all_data["port"]
    ret = []
    for data_entry in port_data:
        data_entry_port = data_entry["portNumber"] 
        if data_entry_port in port_no.keys():
            if float(port_no[data_entry_port]) == 0:
                ret.append((data_entry_port, float(data_entry["receiveBytes"])))
            elif float(port_no[data_entry_port]) == 1:
                ret.append((data_entry_port, float(data_entry["transmitBytes"])))
    if len(ret) == 0:
        sys.stderr.write('WARN: transmitBytes = 0')
    return ret

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("floodlight_ip", type=str, help="floodlight ip address")
    parser.add_argument("port", type=str, help="floodlight incomming port number")
    parser.add_argument("interval", type=str, help="interval time (s)")
    parser.add_argument("switch_id", type=str, help="switch id")
    parser.add_argument("threshold", type=str, help="threshold (bps)")
    parser.add_argument("in_out", type=str, help="traffic comes in or goes out for this port. 0 for in, 1 for out.")
    args = parser.parse_args()
    port_in_out = {}
    port_no = args.port.split(',')
    in_out = args.in_out.split(',')
    index = 0
    for pNumber in port_no:
        port_in_out[pNumber] = in_out[index]
        index += 1

    received = get_throughput(args.floodlight_ip, port_in_out, args.switch_id)
    received.sort(key=lambda r : r[0])
    timerBegin=time.time();
    while 1:
        timerEnd=time.time();
        time.sleep(float(args.interval) - (timerEnd-timerBegin));
        timerBegin=time.time();
        currents = get_throughput(args.floodlight_ip, port_in_out, args.switch_id)
        currents.sort(key=lambda c : c[0])
        index = 0
        strings=""
        pre_thru = 0
        print currents 
        print received
        for k,current in currents:  
            if current < 0 :
                continue
            if current < received[index][1] : 
                throughput = (current + 0xffffffff - received[index][1]) * 8.0 / float(args.interval)
            else :
                throughput = (current - received[index][1]) * 8.0 / float(args.interval)
            if throughput > float(args.threshold) : 
                print "OVER LOAD!!!"
            else :
                strings += str(throughput) + ","
                if index > 0:
                    strings += str(throughput - pre_thru) + ","
                pre_thru = throughput
            received[index] = (received[index][0], current)
            index +=1
        print strings 


