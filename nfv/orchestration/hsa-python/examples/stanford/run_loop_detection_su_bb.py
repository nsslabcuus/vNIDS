'''
    <Run loop detection test on Stanford network>

    Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
    a special exception, as described in included LICENSE_EXCEPTION.txt.
    
Created on Aug 14, 2011

@author: Peyman Kazemian
'''
from examples.utils.network_loader import load_network
from config_parser.cisco_router_parser import cisco_router
from time import time
from headerspace.applications import detect_loop,print_paths

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
            "num_layers":3,
            "fwd_engine_layer":2,
            "input_path":"tf_stanford_backbone",
            "switch_id_multiplier":cisco_router.SWITCH_ID_MULTIPLIER,
            "port_type_multiplier":cisco_router.PORT_TYPE_MULTIPLIER,
            "out_port_type_const":cisco_router.OUTPUT_PORT_TYPE_CONST,
            "remove_duplicates":True,
            }

(ntf,ttf,port_map,port_reverse_map) = load_network(settings)

output_port_addition = cisco_router.PORT_TYPE_MULTIPLIER * \
cisco_router.OUTPUT_PORT_TYPE_CONST

#ports that should be used in loop detection test
loop_port_ids = [
                 port_map["bbra_rtr"]["te7/1"],
                 port_map["bbrb_rtr"]["te7/1"],
                 port_map["bbra_rtr"]["te6/3"],
                 port_map["bbrb_rtr"]["te7/4"],
                 port_map["bbra_rtr"]["te7/2"],
                 port_map["bbrb_rtr"]["te1/1"],
                 port_map["bbra_rtr"]["te6/1"],
                 port_map["bbrb_rtr"]["te6/3"],
                 port_map["bbra_rtr"]["te1/4"],
                 port_map["bbrb_rtr"]["te1/3"],
                 port_map["bbra_rtr"]["te1/3"],
                 port_map["bbrb_rtr"]["te7/2"],
                 port_map["bbra_rtr"]["te7/3"],
                 port_map["bbrb_rtr"]["te6/1"],
                 port_map["boza_rtr"]["te2/3"],
                 port_map["coza_rtr"]["te2/3"],
                 port_map["yozb_rtr"]["te1/3"],
                 port_map["yozb_rtr"]["te1/2"],
                 port_map["yoza_rtr"]["te1/1"],
                 port_map["yoza_rtr"]["te1/2"],
                 port_map["bozb_rtr"]["te2/3"],
                 port_map["cozb_rtr"]["te2/3"],
                 port_map["gozb_rtr"]["te2/3"],
                 port_map["pozb_rtr"]["te2/3"],
                 port_map["goza_rtr"]["te2/3"],
                 port_map["poza_rtr"]["te2/3"],
                 port_map["rozb_rtr"]["te2/3"],
                 port_map["sozb_rtr"]["te2/3"],
                 port_map["roza_rtr"]["te2/3"],
                 port_map["soza_rtr"]["te2/3"],
                 ]

st = time()

loops = detect_loop(ntf,ttf,loop_port_ids,None,output_port_addition)
en = time()
print_paths(loops, port_reverse_map)

print "Found ",len(loops)," loops in ",en-st," seconds."
