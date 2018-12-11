'''
Created on Jul 27, 2012

@author: Peyman Kazemian
'''
from headerspace.tf import TF
from headerspace.hs import headerspace
from utils.wildcard import wildcard_create_bit_repeat
from net_plumbing.net_plumber import NetPlumber
from time import time
from config_parser.cisco_router_parser import cisco_router
from examples.utils.network_loader import net_loader

settings = {"rtr_names":["bbra_rtr",
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
             ],
            "input_path":"../examples/stanford/tf_stanford_backbone",
            "switch_id_multiplier":cisco_router.SWITCH_ID_MULTIPLIER,
            "port_type_multiplier":cisco_router.PORT_TYPE_MULTIPLIER,
            "mid_port_type_const":cisco_router.INTERMEDIATE_PORT_TYPE_CONST,
            }

loader = net_loader(settings)
(map,inv_map) = loader.load_port_map()

#topology
f = TF(1)
f.load_object_from_file("%s/topology.tf"%settings["input_path"])

#net plumber instance
N = NetPlumber(f.length)

#adding links
for rule in f.rules:
  input_ports = rule["in_ports"]
  output_ports = rule["out_ports"]
  for input_port in input_ports:
    for output_port in output_ports:
      N.add_link(input_port, output_port)
     
# add links for intermediate port
f = open("%s/port_map.txt"%settings["input_path"],'r')
for line in f:
  if (not line.startswith("$")) and line != "":
    tokens = line.strip().split(":")
    port = int(tokens[1]) + settings["port_type_multiplier"] * \
    settings["mid_port_type_const"]
    N.add_link(port,port)

# add link for forward engine port
for i in range(len(settings["rtr_names"])):
  fwd_link = (i+1) * settings["switch_id_multiplier"]
  N.add_link(fwd_link,fwd_link)
     
# add a source node at yoza-te1/4
src_port_id = map["yoza_rtr"]["te1/4"]
N.add_link(1,src_port_id)
hs = headerspace(N.length)
hs.add_hs(wildcard_create_bit_repeat(N.length,0x3))
N.add_source("yoza-source", hs, [1])
     
rule_ids = []
for rtr_name in settings["rtr_names"]:
  f = TF(1)
  f.load_object_from_file("%s/%s.tf"%(settings["input_path"],rtr_name)) 
  for rule in f.rules:
    in_ports = rule["in_ports"]
    out_ports = rule["out_ports"]
    match = rule["match"]
    mask = rule["mask"]
    rewrite = rule["rewrite"]
    st = time()
    rule_ids.append(\
            N.add_rule(rtr_name, -1, in_ports, out_ports, match, mask, rewrite)\
            )
    en = time()
    print "Rule Add Time: ",(en-st)*1000,"ms"


