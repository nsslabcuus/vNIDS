#!/usr/bin/env python
# coding=utf-8
__author__ = 'Hongda Li'
#--------------------------------------------------------------------------------
#   I recommend:
#   dst_mac = 00:00:00:00:00:01; dst_ip = 10.10.10.10;
#   inter = 0.01(sec); size = 0; 
#--------------------------------------------------------------------------------

import sys
from scapy.all import *

def option(interface, dst_mac, dst_ip, inter_time, send_count, payload_size, ver):
    src_mac = "74:a0:2f:5f:2b:bd"
    src_ip = "10.130.127.4"
    sendp(  Ether(src=src_mac, dst=dst_mac)/
            IP(proto=252, src=src_ip, dst=dst_ip)/
            Raw(RandBin(payload_size)),
            inter=inter_time, count=send_count, iface=interface, verbose=ver)


if __name__ == '__main__':
    argc = len(sys.argv)
    if argc < 6:
        print 'Usage : python pypacer.py <dst_mac> <dst_ip> <inter> <count> <size> [verbose]'
        exit()

    dst_mac = sys.argv[1]
    dst_ip = sys.argv[2]
    inter = sys.argv[3]
    count = sys.argv[4]
    size = sys.argv[5]
    verbose = 0
    if argc == 7:
        verbose = int(sys.argv[6])

    interface = "ovs-lan"
    option(interface, dst_mac, dst_ip, float(inter), int(count), int(size), verbose)

