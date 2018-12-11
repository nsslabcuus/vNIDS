'''
    <Generates all transfer functions for Stanford backbone network>
    
    Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
    a special exception, as described in included LICENSE_EXCEPTION.txt.
    
Created on Aug 10, 2011

@author: Peyman Kazemian
'''

from examples.example_utils.cisco_tf_generator import generate_transfer_functions

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
            "input_path":"Stanford_backbone",
            "output_path":"tf_stanford_backbone",
            "topology":[("bbra_rtr","te7/3","goza_rtr","te2/1"),
            ("bbra_rtr","te7/3","pozb_rtr","te3/1"),
            ("bbra_rtr","te1/3","bozb_rtr","te3/1"),
            ("bbra_rtr","te1/3","yozb_rtr","te2/1"),
            ("bbra_rtr","te1/3","roza_rtr","te2/1"),
            ("bbra_rtr","te1/4","boza_rtr","te2/1"),
            ("bbra_rtr","te1/4","rozb_rtr","te3/1"),
            ("bbra_rtr","te6/1","gozb_rtr","te3/1"),
            ("bbra_rtr","te6/1","cozb_rtr","te3/1"),
            ("bbra_rtr","te6/1","poza_rtr","te2/1"),
            ("bbra_rtr","te6/1","soza_rtr","te2/1"),
            ("bbra_rtr","te7/2","coza_rtr","te2/1"),
            ("bbra_rtr","te7/2","sozb_rtr","te3/1"),
            ("bbra_rtr","te6/3","yoza_rtr","te1/3"),
            ("bbra_rtr","te7/1","bbrb_rtr","te7/1"),
            ("bbrb_rtr","te7/4","yoza_rtr","te7/1"),
            ("bbrb_rtr","te1/1","goza_rtr","te3/1"),
            ("bbrb_rtr","te1/1","pozb_rtr","te2/1"),
            ("bbrb_rtr","te6/3","bozb_rtr","te2/1"),
            ("bbrb_rtr","te6/3","roza_rtr","te3/1"),
            ("bbrb_rtr","te6/3","yozb_rtr","te1/1"),
            ("bbrb_rtr","te1/3","boza_rtr","te3/1"),
            ("bbrb_rtr","te1/3","rozb_rtr","te2/1"),
            ("bbrb_rtr","te7/2","gozb_rtr","te2/1"),
            ("bbrb_rtr","te7/2","cozb_rtr","te2/1"),
            ("bbrb_rtr","te7/2","poza_rtr","te3/1"),
            ("bbrb_rtr","te7/2","soza_rtr","te3/1"),
            ("bbrb_rtr","te6/1","coza_rtr","te3/1"),
            ("bbrb_rtr","te6/1","sozb_rtr","te2/1"),
            ("boza_rtr","te2/3","bozb_rtr","te2/3"),
            ("coza_rtr","te2/3","cozb_rtr","te2/3"),
            ("goza_rtr","te2/3","gozb_rtr","te2/3"),
            ("poza_rtr","te2/3","pozb_rtr","te2/3"),
            ("roza_rtr","te2/3","rozb_rtr","te2/3"),
            ("soza_rtr","te2/3","sozb_rtr","te2/3"),
            ("yoza_rtr","te1/1","yozb_rtr","te1/3"),
            ("yoza_rtr","te1/2","yozb_rtr","te1/2")],
            "replace_vlans":[None,None,None,None,(83,580),(83,580),None,None,None,None,None,None,(83,580),(83,580),None,None],
            }
generate_transfer_functions(settings)

