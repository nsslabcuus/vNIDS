'''
Created on Sep 18, 2012

@author: peymank
'''
from examples.utils.net_plumber_policy_maker import NetPlumberReachabilityPolicyGenerator
import json 

in_path = "stanford_json_rules"
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

ports = ["te7/4",
        "te7/4",
        "te3/3",
        "te3/3",
        "te3/3",
        "te3/3",
        "te3/3",
        "te3/3",
        "te3/3",
        "te3/3",
        "te3/3",
        "te3/3",
        "te3/3",
        "te3/3",
        "te1/4",
        "te1/4"
        ]

r = NetPlumberReachabilityPolicyGenerator(16,in_path)

commands = {"commands": []}

for i in range(len(rtr_names)):
  (src,data) = r.put_source(rtr_names[i] + ".in", ports[i])
  commands["commands"].extend(data)
  
print "number of commands ",len(commands["commands"])
f = open("policy.json",'w')
f.write(json.dumps(commands, indent=1))
f.close()    
