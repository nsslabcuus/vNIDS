'''
Created on Sep 15, 2012

@author: peyman kazemian
'''
from examples.utils.network_loader import load_network
from config_parser.cisco_router_parser import cisco_router
from utils.wildcard import wildcard_create_bit_repeat
from utils.wildcard_utils import set_header_field
from headerspace.hs import headerspace
from time import time
import json
from headerspace.applications import find_reachability,print_paths

in_path = "stanford_json_rules/tf_rules"
out_path = "stanford_json_rules"

PORT_TYPE_MULTIPLIER = 10000
SWITCH_ID_MULTIPLIER = 100000
rtr_names = ["bbra_rtr",
           "bbrb_rtr",
           "boza_rtr",
           "bozb_rtr",
           "coza_rtr",
           "cozb_rtr",
           "goza_rtr",
           "gozb_rtr",
           "poza_rtr",
           "pozb_rtr",
           "roza_rtr",
           "rozb_rtr",
           "soza_rtr",
           "sozb_rtr",
           "yoza_rtr",
           "yozb_rtr",
             ]

table_id = 0
topo = json.load(open(in_path+"/"+"topology.tf.json"))
topology = {"topology":[]}
for rule in topo["rules"]:
  in_ports = rule["in_ports"]
  out_ports = rule["out_ports"]
  for in_port in in_ports:
    for out_port in out_ports:
      topology["topology"].append({"src":in_port,"dst":out_port})
      
for rtr_name in rtr_names:
  tf = json.load(open(in_path+"/"+rtr_name+".tf.json"))
  table_id += 1
  tf_in = {"rules":[], "ports":[], "id":table_id*10}
  tf_mid = {"rules":[], "ports":[], "id":table_id*10+1}
  tf_out = {"rules":[], "ports":[], "id":table_id*10+2}
  topology["topology"].append({"src":table_id * SWITCH_ID_MULTIPLIER, "dst":table_id * SWITCH_ID_MULTIPLIER + 2 * PORT_TYPE_MULTIPLIER})
  rtr_ports = set()
  for rule in tf["rules"]:
    rule.pop("line")
    rule.pop("file")
    rule.pop("influence_on")
    rule.pop("affected_by")
    rule.pop("inverse_match")
    rule.pop("inverse_rewrite")
    rule.pop("id")
    if (rule["in_ports"][0] % SWITCH_ID_MULTIPLIER == 0):
      mid_port = table_id * SWITCH_ID_MULTIPLIER + 2 * PORT_TYPE_MULTIPLIER
      rule["in_ports"] = [mid_port]
      tf_mid["rules"].insert(0,rule)
      
    elif (rule["in_ports"][0] % SWITCH_ID_MULTIPLIER < PORT_TYPE_MULTIPLIER):
      #input rules
      for elem in rule["in_ports"]:
        rtr_ports.add(elem)
      tf_in["rules"].insert(0,rule)
    else:
      # output rules
      rule_in_ports = []
      for p in rule["in_ports"]:
        rule_in_ports.append(p+PORT_TYPE_MULTIPLIER)
      rule["in_ports"] = rule_in_ports
      tf_out["rules"].insert(0,rule)
      
  tf_in["ports"] = list(rtr_ports)
  tf_out["ports"] = list(rtr_ports)
  for port in rtr_ports:
    topology["topology"].append({"src":port+PORT_TYPE_MULTIPLIER, "dst":port+2*PORT_TYPE_MULTIPLIER})
  f_in = open(out_path+"/"+rtr_name+".in.rules.json",'w')
  f_mid = open(out_path+"/"+rtr_name+".mid.rules.json",'w')
  f_out = open(out_path+"/"+rtr_name+".out.rules.json",'w')
  f_in.write(json.dumps(tf_in, indent=1))
  f_mid.write(json.dumps(tf_mid, indent=1))
  f_out.write(json.dumps(tf_out, indent=1))
  f_in.close()
  f_mid.close()
  f_out.close()

f_topo = open(out_path+"/topology.json",'w')
f_topo.write(json.dumps(topology, indent=1))
  
  
    