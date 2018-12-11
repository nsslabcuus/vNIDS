'''
Created on Sep 19, 2012

@author: peymankazemian
'''
from headerspace.tf import TF
import json

rtr_names = ["atla",
             "chic",
             "hous",
             "kans",
             "losa",
             "newy32aoa",
             "salt",
             "seat",
             "wash"
             ]
PORT_TYPE_MULTIPLIER = 10000
SWITCH_ID_MULTIPLIER = 100000
path = "i2_tfs"
out_path = "i2_json_rules"

table_id = 0
topo = TF(1)
topo.load_object_from_file("%s/%s.tf"%(path,"topology"))
topology = {"topology":[]}
for rule in topo.rules:
  in_ports = rule["in_ports"]
  out_ports = rule["out_ports"]
  for in_port in in_ports:
    for out_port in out_ports:
      topology["topology"].append({"src":in_port,"dst":out_port})
topo.save_as_json("%s/%s.json"%(path,"topology"))

for rtr in rtr_names:
  tf = TF(1)
  tf.load_object_from_file("%s/%s.tf"%(path,rtr))
  tf.save_as_json("%s/%s.tf.json"%(path,rtr))
  table_id += 1
  tf_in = {"rules":[], "ports":[], "id":table_id*10}
  tf_out = {"rules":[], "ports":[], "id":table_id*10+1}
  topology["topology"].append({"src":table_id * SWITCH_ID_MULTIPLIER, "dst":table_id * SWITCH_ID_MULTIPLIER + PORT_TYPE_MULTIPLIER})
  rtr_ports = set()
  for rule in tf.rules:
    rule.pop("line")
    rule.pop("file")
    rule.pop("influence_on")
    rule.pop("affected_by")
    rule.pop("inverse_match")
    rule.pop("inverse_rewrite")
    rule.pop("id")
    if rule["match"]:
      rule["match"] = rule["match"].__str__(0)
    if rule["rewrite"]:
      rule["rewrite"] = rule["rewrite"].__str__(0)
    if rule["mask"]:
      rule["mask"] = rule["mask"].__str__(0)
    if (rule["in_ports"][0] % SWITCH_ID_MULTIPLIER == 0):
      mid_port = table_id * SWITCH_ID_MULTIPLIER + 2 * PORT_TYPE_MULTIPLIER
      rule["in_ports"] = [mid_port]
      tf_out["rules"].append(rule)
    else:
      for elem in rule["in_ports"]:
        rtr_ports.add(elem)
      tf_in["rules"].append(rule)
  tf_in["ports"] = list(rtr_ports)
  tf_out["ports"] = list(rtr_ports)
  f_in = open(out_path+"/"+rtr+".in.rules.json",'w')
  f_out = open(out_path+"/"+rtr+".out.rules.json",'w')
  f_in.write(json.dumps(tf_in, indent=1))
  f_out.write(json.dumps(tf_out, indent=1))
  f_in.close()
  f_out.close()
   

f_topo = open(out_path+"/topology.json",'w')
f_topo.write(json.dumps(topology, indent=1))