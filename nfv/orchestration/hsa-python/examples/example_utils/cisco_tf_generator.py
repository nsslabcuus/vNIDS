'''
    <Generate transfer functions for a network of cisco routers>
    
    Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
    a special exception, as described in included LICENSE_EXCEPTION.txt.
    
Created on Aug 10, 2011

@author: Peyman Kazemian
'''
from time import time
from config_parser.cisco_router_parser import cisco_router
from headerspace.tf import TF
import json 

'''
settings is a dictionary containing the following:
@key: @value
@required "rtr_names": list of router names (order is important. loader should
have the same order)
@required "input_path": input path relative to current directory
@required "output_path": output path relative to current directory
@optional "topology" a list of (from_rtr,from_port,to_rtr,to_port)
@optional "hs_format": a hs_format dictionary
@optional "arp_table_file_sfx": arp table file suffix (def: _arp_table.txt)
@optional "mac_table_file_sfx": mac table file suffix (def: _mac_table.txt)
@optional "config_file_sfx": config file suffix (def: _config.txt)
@optional "spanning_tree_file_sfx": (def: _spanning_tree.txt)
@optional "route_table_file_sfx": route table file suffix (def: _route.txt)
@optional "replace_vlans": (hack!) a vlan to be replaced instead of subport 
vlans.
@optional "fwd_table_only": true or false (def: false)
@optional "optimize_fwd_table": true or false (def: true)
'''

def generate_transfer_functions(settings):
  st = time()
  
  if ("replace_vlans" in settings.keys()):
    has_replaced_vlan = True
  else:
    has_replaced_vlan = False
    
  if "arp_table_file_sfx" in settings.keys():
    arp_sfx = settings["arp_table_file_sfx"]
  else:
    arp_sfx = "_arp_table.txt"
  if "mac_table_file_sfx" in settings.keys():
    mac_sfx = settings["mac_table_file_sfx"]
  else:
    mac_sfx = "_mac_table.txt"
  if "config_file_sfx" in settings.keys():
    config_sfx = settings["config_file_sfx"]
  else:
    config_sfx = "_config.txt"
  if "spanning_tree_file_sfx" in settings.keys():
    span_sfx = settings["spanning_tree_file_sfx"]
  else:
    span_sfx = "_spanning_tree.txt"
  if "route_table_file_sfx" in settings.keys():
    route_sfx = settings["route_table_file_sfx"]
  else:
    route_sfx = "_route.txt"

  # generate transfer functions
  L = 0
  id = 1
  cs_list = {}
  for i in range(len(settings["rtr_names"])):
    rtr_name = settings["rtr_names"][i]
    cs = cisco_router(id)
    if has_replaced_vlan:
      cs.set_replaced_vlan(settings["replace_vlans"][i])
    if "hs_format" in settings.keys():
      cs.set_hs_format(settings["hs_format"])
    L = cs.hs_format["length"]
    tf = TF(L)
    tf.set_prefix_id(rtr_name)
    cs.read_arp_table_file("%s/%s%s"%(settings["input_path"],rtr_name,arp_sfx))
    cs.read_mac_table_file("%s/%s%s"%(settings["input_path"],rtr_name,mac_sfx))
    cs.read_spanning_tree_file("%s/%s%s"%\
                               (settings["input_path"],rtr_name,span_sfx))
    cs.read_config_file("%s/%s%s"%(settings["input_path"],rtr_name,config_sfx))
    cs.read_route_file("%s/%s%s"%(settings["input_path"],rtr_name,route_sfx))
    if ("optimize_fwd_table" not in settings.keys() or \
        settings["optimize_fwd_table"]):
      cs.optimize_forwarding_table()
    if ("fwd_table_only" in settings.keys() and settings["fwd_table_only"]):
      cs.generate_port_ids_only_for_output_ports()
      cs.generate_fwd_table_tf(tf)
    else:
      cs.generate_port_ids([])
      cs.generate_transfer_function(tf)
    tf.save_as_json("%s/%s.tf.json"%(settings["output_path"],rtr_name))
    tf.save_object_to_file("%s/%s.tf"%(settings["output_path"],rtr_name))
    id += 1
    cs_list[rtr_name] = cs
    
  #generate port maps
  f = open("%s/port_map.json"%settings["output_path"],'w')
  port_map = {}
  for rtr in cs_list.keys():
    cs = cs_list[rtr]
    port_map[rtr] = cs.port_to_id
  f.write(json.dumps(port_map))
  f.close()
  
  #write topology:
  if "topology" in settings.keys():
    print "===Generating Topology==="
    out_port_addition = cisco_router.PORT_TYPE_MULTIPLIER * \
          cisco_router.OUTPUT_PORT_TYPE_CONST
    topology = settings["topology"]
    tf = TF(L)
    for (from_router,from_port,to_router,to_port) in topology:
        from_cs = cs_list[from_router]
        to_cs = cs_list[to_router]
        rule = TF.create_standard_rule(\
                      [from_cs.get_port_id(from_port) + out_port_addition],\
                        None,[to_cs.get_port_id(to_port)],\
                        None, None, "", [])
        tf.add_link_rule(rule)
        rule = TF.create_standard_rule(\
                      [to_cs.get_port_id(to_port) + out_port_addition], \
                        None,[from_cs.get_port_id(from_port)], \
                        None, None, "", [])
        tf.add_link_rule(rule)
    tf.save_as_json("%s/topology.tf.json"%settings["output_path"])
    tf.save_object_to_file("%s/topology.tf"%settings["output_path"])
    
  en = time()
  print "completed in ",en - st, "seconds"