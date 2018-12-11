'''
Created on Sep 15, 2012

@author: peymank
'''
import sys
sys.path.append("../..")
import json, socket
from examples.utils.net_plumber_policy_maker import NetPlumberReachabilityPolicyGenerator

def send_command(s,data):
  for d in data:
    command = json.dumps(d, indent=1)
    print "sending command ",command
    s.send(command)
    response = s.recv(1024)
    print "received response:", response

TCP_IP = '127.0.0.1'
TCP_PORT = 6543
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))

#r = NetPlumberReachabilityPolicyGenerator(11,"../google/google_sdn_tfs")
r = NetPlumberReachabilityPolicyGenerator(16,"../stanford/stanford_json_rules")

sources = {}

while (True):
  input = raw_input("Enter command:")
  if input == "reachability":
    src = raw_input("Enter source:")
    src_port = raw_input("Enter source port:")
    dst = raw_input("Enter destination:")
    dst_port = raw_input("Enter destination port:")
      
    if src not in sources:
      sources[src] = {}
    if src_port not in sources[src]:
      if src_port == "all":
        (src_id,data) = r.put_source(src)
      else:
        (src_id,data) = r.put_source(src,src_port)
      sources[src][src_port] = src_id
      send_command(s,data)
      
    if dst_port == "all":
      #data = r.put_probe(dst, sources[src][src_port])
      pass
    else:
      data = r.put_probe(dst, sources[src][src_port],dst_port)
    send_command(s,data)
    
  elif input == "linkup":
    src = raw_input("Enter source id:")
    dst = raw_input("Enter target id:")
    data = {"method":"add_link",
            "id":1,
            "jsonrpc":"2.0",
            "params":{"from_port":int(src),
                      "to_port":int(dst)}
              }
    send_command(s,[data])
  elif input == "linkdown":
    src = raw_input("Enter source id:")
    dst = raw_input("Enter target id:")
    data = {"method":"remove_link",
            "id":1,
            "jsonrpc":"2.0",
            "params":{"from_port":int(src),
                      "to_port":int(dst)}
              }
    send_command(s,[data])
  elif input == "print":
    sw = raw_input("Enter table name:")
    data = r.print_table(sw)
    send_command(s,data)
  elif input == "remove":
    sw = raw_input("Enter switch name:")
    rule_id = raw_input("Enter a rule id:")
    data = r.delete_rule(sw, rule_id)
    send_command(s,data)
  elif input == "end" or input == "q":
    break


