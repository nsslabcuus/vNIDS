'''
    <Generate OpenFlow rules to emulate behavior of Stanford Network>
    
    Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
    a special exception, as described in included LICENSE_EXCEPTION.txt.
    
Created on Mar 31, 2012

@author: Peyman Kazemian
'''
from config_parser.transfer_function_to_openflow import OpenFlow_Rule_Generator
from headerspace.tf import TF

format = {}
format["ip_dst_pos"] = 0
format["ip_dst_len"] = 4
format["length"] = 4

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

for rtr_name in rtr_names:
    f = TF(1)
    f.load_object_from_file("tf_simple_stanford_backbone/%s.tf"%rtr_name)
    #OFG = OpenFlow_Rule_Generator(f,ciscoRouter(1).HS_FORMAT())
    OFG = OpenFlow_Rule_Generator(f,format)
    OFG.generate_of_rules("stanford_openflow_rules/%s.of"%rtr_name)