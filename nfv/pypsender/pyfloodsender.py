__author__ = 'zhizhong pan'

import sys
import os
from scapy.all import *
from pyconfparser import parser_config

work_dir = os.getcwd()

config_all = {}

def option(inter_time, send_count, payload_size, operation, instance_id, ver):
    config_traffic = []
    config_instance = config_all[instance_id]
    for config_entry in config_instance:
        if config_entry[0] == 'traffic':
            config_traffic = config_entry[1:]

    interface, src_ip, src_port, src_mac, dst_ip, dst_port, dst_mac = config_traffic

    if operation == '1':
        sendp(Ether(src=src_mac, dst=dst_mac)/
              IP(src=src_ip, dst=dst_ip)/
              TCP(sport=int(src_port), dport=int(dst_port), flags='S')/
              Raw(RandBin(payload_size)),
              inter=inter_time, count=send_count, iface=interface, verbose=ver)

    elif operation == '2':
        sendp(Ether(src=src_mac, dst=dst_mac)/
              IP(src=src_ip, dst=dst_ip, proto='tcp')/
              TCP(sport=int(src_port), dport=int(dst_port))/
              Raw(RandBin(payload_size)),
              inter=inter_time, count=send_count, iface=interface, verbose=ver)

    elif operation == '3':
        sendp(Ether(src=src_mac, dst=dst_mac)/
              IP(src=src_ip, dst=dst_ip, proto='udp')/
              UDP(sport=int(src_port), dport=int(dst_port))/
              Raw(RandBin(payload_size)),
              inter=inter_time, count=send_count, iface=interface, verbose=ver)

    elif operation == '4':
        sendp(Ether(src=src_mac, dst=dst_mac)/
              IP(src=src_ip, dst=dst_ip, proto='icmp')/
              ICMP()/
              Raw(RandBin(payload_size)),
              inter=inter_time, count=send_count, iface=interface, verbose=ver)

    else:
        print "Option not valid."
        sys.exit()


if __name__ == '__main__':
    argc = len(sys.argv)
    if argc < 6:
        print 'Usage : python pyfloodsender.py <inter> <count> <size> <[1|2|3|4]> <instance id> [verbose]'
        print 'flood type : 1) syn, 2) tcp, 3)udp, 4) icmp'
        exit()

    inter = sys.argv[1]
    count = sys.argv[2]
    size = sys.argv[3]
    op = sys.argv[4]
    ins_id = sys.argv[5]
    verbose = 0
    if argc == 7:
        verbose = int(sys.argv[6])

    config_all = parser_config(work_dir + '/' + 'pypsender.cfg')

    option(float(inter), int(count), int(size), op, ins_id, verbose)
