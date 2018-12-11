'''
Created on Sep 9, 2012

@author: Peyman Kazemian
'''
from headerspace.tf import TF
from time import time
from config_parser.openflow_protobuf_parser import OFProtobufParser

'''
settings is a dictionary containing the following:
@key: @value
@required "zone_names": list of zone names 
@required "input_path": input path relative to current directory
@required "output_path": output path relative to current directory
@optional "hs_format": a hs_format dictionary
'''

def generate_transfer_functions(settings):
  st = time()
  parser = OFProtobufParser()
  for zone_name in settings["zone_names"]:
    print "==== procesing ",zone_name," ===="
    parser.read_flows_ascii("%s/%s-flows.proto"%(settings["input_path"],zone_name))
    parser.read_multipath_ascii("%s/%s-multipath.proto"%(settings["input_path"],zone_name))
    parser.read_topology_ascii("%s/%s-topology.proto"%(settings["input_path"],zone_name))
  parser.genearte_port_map()
  parser.generate_graph_file(settings["output_path"])
  parser.generate_rules(settings["output_path"])
  en = time()

  print "total switch count: ", len(parser.port_map.keys())
  print "switched from port map: ",parser.port_map.keys()
  print "total switch count: ", len(parser.flows.keys())
  print "switched from flows: ",parser.flows.keys()
  flow_count = 0
  mp_count = 0
  for rtr in parser.flows:
    for port in parser.multipath[rtr]:
      mp_count += len(parser.multipath[rtr][port])
    print "Switch ",rtr," has ",len(parser.port_map[rtr])," ports and ",len(parser.flows[rtr]), " flows."
    flow_count += len(parser.flows[rtr])
  print "Total flow count: ",flow_count
  print "Total rule nodes: ",flow_count + mp_count
  print "parsing time: ",(en-st)
  return parser