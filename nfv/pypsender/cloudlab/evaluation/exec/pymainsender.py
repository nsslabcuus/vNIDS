__author__ = 'zhizhong pan'
#------------------------------------------------------------------------------
#   This script sends messages to the firewall instances.
#   Dependencies: 
#       pypsender.cfg. -- located in ../etc/ 
#------------------------------------------------------------------------------

from scapy.all import *
import argparse
import struct
import re
import socket 
import os

work_dir = os.getcwd()

# key   : instance id
# value : config info 
# config_table may look like: 
#   config_table = {
#       '1' : [
#               [ 'traffic', 'ovs-lan', '10.130.127.1', ... ],
#               [ 'maintain', 'ovs-lan', '10.130.127.1', ... ],
#               ...
#               [ 'maintain', 'ovs-lan', '10.130.127.2', ... ]
#           ],
#       '2' : [
#               .
#               .
#               .
#           ],
#       '3' : [
#               .
#               .
#               .
#           ],
#       .
#       .
#       .
#   }
#
config_table = {}

# key   : instance id
# value : maintenance operation dic
maintenance_table = {}

# key   : protocol
# value : protocol number
protocol_table = {'tcp': 6, 'icmp': 1, 'udp': 17, 'ipv4': 4}

def cidr2ip(prefix):
    return socket.inet_ntoa(struct.pack("!I", ~(0xffffffff << (32 - prefix)) & 0xffffffff))

def ip2int(address):
    return struct.unpack('!I', socket.inet_aton(address))[0]

def int2ip(address):
    return socket.inet_ntoa(struct.pack("!I", address))

def assemble_entry_with_index(src_ip, src_ip_mask, dst_ip, dst_ip_mask, src_port_min,
                              src_port_max, dst_port_min, dst_port_max,  protocol, action, index):
    act_bin = 0
    protocol_no = protocol_table[protocol]
    if action == 'allow':
        act_bin = 1

    return struct.pack('!IIIIHHHHBBHB', ip2int(src_ip), ip2int(cidr2ip(src_ip_mask)), ip2int(dst_ip),
                       ip2int(cidr2ip(dst_ip_mask)), int(src_port_min), int(src_port_max), int(dst_port_min),
                       int(dst_port_max), protocol_no, int(act_bin), int(index), 10)

def assemble_entry(src_ip, src_ip_mask, dst_ip, dst_ip_mask, src_port_min,
                   src_port_max, dst_port_min, dst_port_max,  protocol, action):
    act_bin = 0
    protocol_no = protocol_table[protocol]
    if action == 'allow':
        act_bin = 1

    return struct.pack('!IIIIHHHHBBxxB', ip2int(src_ip), ip2int(cidr2ip(src_ip_mask)), ip2int(dst_ip),
                       ip2int(cidr2ip(dst_ip_mask)), int(src_port_min), int(src_port_max), int(dst_port_min),
                       int(dst_port_max), protocol_no, int(act_bin), 10)

def print_rule(rule):
    if len(rule) == 10:
        print('Source IP : ' + rule[0] + '/' + rule[1] + '\n' +
              'Destination IP : ' + rule[2] + '/' + rule[3] + '\n' +
              'Source port : ' + rule[4] + '/' + rule[5] + '\n' +
              'Destination Port : ' + rule[6] + '/' + rule[7] + '\n' +
              'Protocol : ' + rule[8] + '\n' +
              'Action : ' + rule[9])
    elif len(rule) == 11:
        print('Source IP : ' + rule[0] + '/' + rule[1] + '\n' +
              'Destination IP : ' + rule[2] + '/' + rule[3] + '\n' +
              'Source port : ' + rule[4] + '/' + rule[5] + '\n' +
              'Destination Port : ' + rule[6] + '/' + rule[7] + '\n' +
              'Protocol : ' + rule[8] + '\n' +
              'Action : ' + rule[9] + '\n' +
              'Index : ' + rule[10])

def send_packet_by_instance(instance_id, verbose):
    if instance_id not in config_table:
        print(instance_id + " is not in the config file! please check it!!")
        return False

    config_instance = config_table[instance_id]
    for config_entry in config_instance:
        if config_entry[0] == 'maintain':
            config_maintain = config_entry[1:]

    interface, src_ip, src_mac, dst_ip, dst_mac = config_maintain
    
    # Each (k,value) paire stores all rules for one OPERATION.
    for k, value in maintenance_table[instance_id].items():
        if verbose is True:
            print('INSTANCE : ' + instance_id + '     OP : ' + k)
        total_length = len(value)
        TL = total_length;
        # Each round will send out one packet, with 40 rules max.
        while (total_length > 0):
            length_to_send = 40
            if total_length < 40:
                length_to_send = total_length
            total_length -= length_to_send
            v = value[TL-(total_length+length_to_send):(TL-total_length)] 
            if k == 'append':
                packt = struct.pack('!BBH', 0, 0, len(v))
                for rule in v:
                    if len(rule) < 10:
                        print "append rule: lack of field."
                        return False
                    rule_bin = assemble_entry(rule[0], int(rule[1]), rule[2], int(rule[3]),
                                          rule[4], rule[5], rule[6], rule[7], rule[8], rule[9])
                    packt += rule_bin
                    if verbose is True:
                        print_rule(rule)

            elif k == 'replace':
                packt = struct.pack('!BBH', 0, 1, len(v))
                for rule in v:
                    if len(rule) < 11:
                        print "replace rule: lack of field."
                        return False
                    rule_bin = assemble_entry(rule[0], int(rule[1]), rule[2], int(rule[3]),
                                          rule[4], rule[5], rule[6], rule[7], rule[8], rule[9], rule[10])
                    packt += rule_bin
                    if verbose is True:
                        print_rule(rule)

            elif k == 'insert':
                packt = struct.pack('!BBH', 0, 2, len(v))
                for rule in v:
                    if len(rule) < 11:
                        print "insert rule: lack of field."
                        return False
                    rule_bin = assemble_entry(rule[0], int(rule[1]), rule[2], int(rule[3]),
                                          rule[4], rule[5], rule[6], rule[7], rule[8], rule[9], rule[10])
                    packt += rule_bin
                    if verbose is True:
                        print_rule(rule)

            elif k == 'delete':
                packt = struct.pack('!BBH', 0, 3, len(v))
                for rule in v:
                    if len(rule) < 10:
                        print "delete rule: lack of field."
                        return False
                    rule_bin = assemble_entry(rule[0], int(rule[1]), rule[2], int(rule[3]),
                                          rule[4], rule[5], rule[6], rule[7], rule[8], rule[9])
                    packt += rule_bin
                    if verbose is True:
                        print_rule(rule)

            elif k == 'check':
                packt = struct.pack('!BBH', 0, 4, len(v))
                for rule in v:
                    if len(rule) < 10:
                        print "check rule: lack of field."
                        return False
                    rule_bin = assemble_entry(rule[0], int(rule[1]), rule[2], int(rule[3]),
                                      rule[4], rule[5], rule[6], rule[7], rule[8], rule[9])
                    packt += rule_bin
                    if verbose is True:
                        print_rule(rule)

            elif k == 'clear':
                packt = struct.pack('!BB', 0, 5)
       
            elif k == 'p_append':
                mac_addr = v[0][0].split(':')
                # set mac address. 
                packt = struct.pack('!BBBBBBBB', 0, 6,
                                     int(mac_addr[0][0])*16 + int(mac_addr[0][1]),
                                     int(mac_addr[1][0])*16 + int(mac_addr[1][1]),
                                     int(mac_addr[2][0])*16 + int(mac_addr[2][1]),
                                     int(mac_addr[3][0])*16 + int(mac_addr[3][1]),
                                     int(mac_addr[4][0])*16 + int(mac_addr[4][1]),
                                     int(mac_addr[5][0])*16 + int(mac_addr[5][1]))

            elif k == 'p_delete':
                mac_addr = v[0][10].split(':')
                # set mac address. 
                packt = struct.pack('!BBBBBBBBH', 0, 8, 
                                     int(mac_addr[0][0])*16 + int(mac_addr[0][1]),
                                     int(mac_addr[1][0])*16 + int(mac_addr[1][1]),
                                     int(mac_addr[2][0])*16 + int(mac_addr[2][1]),
                                     int(mac_addr[3][0])*16 + int(mac_addr[3][1]),
                                     int(mac_addr[4][0])*16 + int(mac_addr[4][1]),
                                     int(mac_addr[5][0])*16 + int(mac_addr[5][1]),
                                     len(v));
                for rule in v:
                    if len(rule) < 11:
                        print "p_delete rule: lack of field."
                        return False
                    rule_bin = assemble_entry(rule[0], int(rule[1]), rule[2], int(rule[3]),
                                      rule[4], rule[5], rule[6], rule[7], rule[8], rule[9])
                    packt += rule_bin
                    if verbose is True:
                        print_rule(rule)
        
            elif k == 'p_delete_end':
                mac_addr = v[0][0].split(':')
                # set mac address. 
                packt = struct.pack('!BBBBBBBB', 0, 9,
                                     int(mac_addr[0][0])*16 + int(mac_addr[0][1]),
                                     int(mac_addr[1][0])*16 + int(mac_addr[1][1]),
                                     int(mac_addr[2][0])*16 + int(mac_addr[2][1]),
                                     int(mac_addr[3][0])*16 + int(mac_addr[3][1]),
                                     int(mac_addr[4][0])*16 + int(mac_addr[4][1]),
                                     int(mac_addr[5][0])*16 + int(mac_addr[5][1]))

            elif k == 'print':
                packt = struct.pack('!BB', 1, 0)

            sendp(Ether(src=src_mac, dst=dst_mac)/IP(src=src_ip, dst=dst_ip, proto=253)/packt,
                                      iface=interface, verbose=verbose)
        if verbose is True:
            print('++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')


def send_packet(verbose):
    for k, v in maintenance_table.items():
        send_packet_by_instance(k, verbose)


def parse_rule_file(infile_list):
    for infile in infile_list:
        for line in infile:
            line_list = [rule.strip() for rule in re.split(',|/', line)]
            instance_id = line_list[0]
            op = line_list[1]
            rule = line_list[2:]
            
            #set icmp rule all port arg to zero
            if len(rule) >= 10 and rule[8] == 'icmp':
                rule[4] = rule[5] = rule[6] = rule[7] = '0'

            if instance_id not in maintenance_table:
                maintenance_table.update({instance_id: {op: [rule]}})
            else:
                if op not in maintenance_table[instance_id]:
                    maintenance_table[instance_id][op] = [rule]
                else:
                    maintenance_table[instance_id][op].append(rule)

def send_notify_packet(instance_id_list, verbose):
    for instance_id in instance_id_list:
        instance_id = str(instance_id)
        if instance_id not in config_table:
            print(instance_id + " is not in the config file! please check it!!")
            return False

        config_instance = config_table[instance_id]
        for config_entry in config_instance:
            if config_entry[0] == 'maintain':
                config_maintain = config_entry[1:]

        interface, src_ip, src_mac, dst_ip, dst_mac = config_maintain

        if verbose is True:
            print('++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
            print('INSTANCE : ' + instance_id + '     IS NOTIFIED')
            print('++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')

        sendp(Ether(src=src_mac, dst=dst_mac)/IP(src=src_ip, dst=dst_ip, proto=254)/'NOTIFY',
                  iface=interface, verbose=verbose)

"""
    Parse the configuratio file. 
"""
def parser_config(file_name):
    config_file = open(file_name, 'r')
    config_all = {}
    for item in config_file:
        config_list = item.strip().split(",")
        if config_list[0][0] != '#':
            instance_no = config_list[0]
            if instance_no not in config_all:
                config_all[instance_no] = []
            config_all[instance_no].append(config_list[1:])

    return config_all



if __name__ == '__main__':

    config_table = parser_config(work_dir + '/../etc/pypsender.cfg')
    parser = argparse.ArgumentParser(description='Sending the maintenance packet')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose the output of maintenance action')

    # create sub-commands to get entry from file or command line or debug
    info_source_parser = parser.add_subparsers(help='get maintenance info from file or command line or just debug')

    # file input parser
    file_parser = info_source_parser.add_parser('file', help='get maintenance from file')
    file_parser.add_argument('infile', metavar='FILENAME', nargs='+', type=argparse.FileType('r'), default=sys.stdin)
    file_parser.add_argument('count', type=float)

    # parser maintenance info form commandline
    command_line_parser = info_source_parser.add_parser('command', help='get maintenance from command line')
    # file_parser.add_argument('', metavar='FILENAME', )

    # notify parser  
    notify_parser = info_source_parser.add_parser('notify', help='notify firewall by instance id')
    notify_parser.add_argument('instance_id_list', metavar='N', type=int, nargs='+', help='an integer list for the instance id')


    # just for debug will not accept other argument
    debug_parser = info_source_parser.add_parser('debug', help='will print the whole file wall')

    args = parser.parse_args()
    if 'infile' in args:
        parse_rule_file(args.infile)
        index = 0
        count = args.count
        while index < count:
            send_packet(args.verbose)
            index += 1

    if 'instance_id_list' in args:    
        send_notify_packet(args.instance_id_list, args.verbose) 


