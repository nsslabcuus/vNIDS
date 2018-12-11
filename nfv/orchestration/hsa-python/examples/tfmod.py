#!/usr/bin/python

import argparse
import json
import os
from config_parser.transfer_function_to_openflow import OpenFlow_Rule_Generator 
from config_parser.cisco_router_parser import cisco_router
from headerspace.tf import TF
from utils.wildcard_utils import set_header_field
from utils.wildcard import wildcard_create_bit_repeat
from utils.helper import dotted_subnet_to_int


OUTPORT_CONST = cisco_router.OUTPUT_PORT_TYPE_CONST * cisco_router.PORT_TYPE_MULTIPLIER
INTER_CONST = cisco_router.INTERMEDIATE_PORT_TYPE_CONST * cisco_router.PORT_TYPE_MULTIPLIER

def get_fwd_port_id(a_port):
  return int(a_port / cisco_router.SWITCH_ID_MULTIPLIER) * cisco_router.SWITCH_ID_MULTIPLIER

ofg = OpenFlow_Rule_Generator(None,cisco_router.HS_FORMAT())
def get_openflow_rule(rule,inv_mapf):
  in_ports = "in_ports:"
  for p in rule["in_ports"]:
    in_ports = in_ports + inv_mapf[p] + ","
  in_ports = in_ports[0:-1]
  out_ports = "out_ports:"
  if len(rule["out_ports"]) > 0:
    for p in rule["out_ports"]:
      out_ports = out_ports + inv_mapf[p] + ","
  else:
    out_ports = out_ports + "None,"
  out_ports = out_ports[0:-1]
  of_rule = ofg.parse_rule(rule)
  (match,rw) = ofg.pretify(of_rule)
  return "%s%s; %s%s;"%(match,in_ports,rw,out_ports)

def get_stage(rule):
  if len(rule["in_ports"]) == 0: 
    return "in"
  sample = rule["in_ports"][0]
  if sample % cisco_router.SWITCH_ID_MULTIPLIER == 0:
    return "mid"
  elif sample % cisco_router.SWITCH_ID_MULTIPLIER < cisco_router.PORT_TYPE_MULTIPLIER:
    return "in"
  else:
    return "out"

parser = argparse.ArgumentParser(description='Command line tool to view/edit transfer functions')
parser.add_argument('rtr_name', 
                   help='name of the router to work on its transfer function.')
parser.add_argument("--view", nargs=1, metavar=('table'),
                    help="view rules in table (table: in/mid/out).")
parser.add_argument("--delete", nargs=2, metavar=('table','rule_index'),
                    help="delete rule_index from table (table: in/mid/out).")
parser.add_argument("--add", nargs=3, metavar=('table','rule_index','rule'),
                    help="add to table a rule at index rule_index. rule is a\
                    comma separated list of field=value or new_filed=new_value.\
                    example: in_port=te1/1:te2/2,ip_dst=10.0.1.0/24,new_vlan=10,out_port=te1/2.\
                    field can be vlan, ip_src, ip_dst, ip_proto, transport_src, trnsport_dst.\
                    in_port and out_port specify the input and output ports, separated by a column.\
                    table is either in,mid or out.")
parser.add_argument("-m", "--map_file", default="port_map.json",
                    help="Port map file name.")
parser.add_argument("-p", "--data_path", default=".",
                    help="Path to where the json transfer function files are stored")
args = parser.parse_args()

f = open("%s/%s"%(args.data_path,args.map_file),'r')
mapf = json.load(f)
inv_mapf = {}
for rtr in mapf:
  for port in mapf[rtr]:
    inv_mapf[int(mapf[rtr][port])] = "%s-%s"%(rtr,port)
    inv_mapf[int(mapf[rtr][port])+OUTPORT_CONST] = "%s-%s"%(rtr,port)
    inv_mapf[int(mapf[rtr][port])+INTER_CONST] = "^%s-%s"%(rtr,port)
  fwd_id = get_fwd_port_id(int(mapf[rtr][port]))
  inv_mapf[fwd_id] = "FWD-ENGINE"
  
tfs = {}   
files_in_dir = os.listdir(args.data_path)
for file_in_dir in files_in_dir:
  if file_in_dir.endswith(".tf.json"):
    tf = TF(1)
    tf.load_from_json("%s/%s"%(args.data_path,file_in_dir))
    tfs[file_in_dir[0:-8]] = tf
    
if args.view:
  f = tfs[args.rtr_name]
  stage = args.view[0]
  i = 1
  for rule in f.rules:
    if stage == get_stage(rule):
      print i,":",get_openflow_rule(rule,inv_mapf)
    i = i + 1;
    
    