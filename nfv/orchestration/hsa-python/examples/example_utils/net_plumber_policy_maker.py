'''
Created on Sep 15, 2012

@author: Peyman Kazemian
'''
import json 
from utils.wildcard import *
from config_parser.openflow_protobuf_parser import OFProtobufParser
from utils.wildcard_utils import set_header_field
from utils.helper import dotted_ip_to_int

class NetPlumberReachabilityPolicyGenerator:
  
  def __init__(self,length,input_path):
    self.length = length
    self.input_path = input_path
    self.PORT_TYPE_MULTIPLIER = 10000
    self.last_id = 0
    self.map = json.load(open("%s/port_map.json"%(self.input_path)))
    
  def put_source(self, source_switch, iport = None):
    commands = []
    source = json.load(open("%s/%s.rules.json"%(self.input_path,source_switch)))
    if (iport == None):
      a_src_port = source["ports"][0]
    else:
      source_switch = (source_switch.split("."))[0]
      a_src_port = self.map[source_switch][iport]
    command = {"id":self.last_id,
               "jsonrpc":"2.0",
               "method":"add_link",
               "params":{"from_port":a_src_port+self.PORT_TYPE_MULTIPLIER*5,
                         "to_port":a_src_port}
               }
    commands.append(command)
    self.last_id += 1
    wc = wildcard_create_bit_repeat(self.length,0x3)
    format = {"nw_src_pos":0, "nw_dst_pos":4, "dl_type_pos":8, "nw_tos_pos":10,
                   "nw_src_len":4, "nw_dst_len":4, "dl_type_len":2, "nw_tos_len":1,
                   "length":11
                   }  
    #set_header_field(format, wc, "nw_dst", dotted_ip_to_int("10.64.0.0"), 16)  
    
    command = {"id":self.last_id,
               "jsonrpc":"2.0",
               "method":"add_source",
               "params": {
                    "ports":[a_src_port+self.PORT_TYPE_MULTIPLIER*5],
                    "hs":{"list":[wildcard_to_str(wc)],
                          "diff":[[]]
                          }
                }
             }
    commands.append(command)
    return (source["id"],commands)
  
  def put_probe(self, dest_switch, source_id, iport = None):
    commands = []
    dst_ports = []
    destination = json.load(open("%s/%s.rules.json"%(self.input_path,dest_switch)))
    if iport == None:
      for port in destination["ports"]:
        command = {"id":self.last_id,
                 "jsonrpc":"2.0",
                 "method":"add_link",
                 "params":{
                           "from_port":port,
                           "to_port":port+self.PORT_TYPE_MULTIPLIER*5
                           }
                   }
        self.last_id += 1
        commands.append(command)
        dst_ports.append(port+self.PORT_TYPE_MULTIPLIER*5)
    else:
      dest_switch = (dest_switch.split("."))[0]
      port_id = self.map[dest_switch][iport]
      command = {"id":self.last_id,
                 "jsonrpc":"2.0",
                 "method":"add_link",
                 "params":{
                           "from_port":port_id,
                           "to_port":port_id+self.PORT_TYPE_MULTIPLIER*5
                           }
                   }
      self.last_id += 1
      commands.append(command)
      dst_ports.append(port_id+self.PORT_TYPE_MULTIPLIER*5)
    
    command = {"id":self.last_id,
               "jsonrpc":"2.0",
               "method":"add_source_probe",
               "params":{
                         "ports":dst_ports,
                         "mode":"existential",
                         "filter":{"type":"true"},
                         "test":{"type":"path",
                                 "pathlets":[
                                 {"type":"last_tables", "tables":[source_id]}
                                 ]
                                 }
                         }
             }
    commands.append(command)
    self.last_id += 1 
    return commands
  
  def delete_rule(self, m_switch, id):
    sw = json.load(open("%s/%s.rules.json"%(self.input_path,m_switch)))
    rule_id = (sw["id"] << 32) + int(id)
    command = {"id":self.last_id,
              "jsonrpc":"2.0",
              "method":"remove_rule",
              "params":{
                        "node":rule_id
                        }
                }
    self.last_id += 1
    return [command] 
    
  def print_table(self, switch):
    sw = json.load(open("%s/%s.rules.json"%(self.input_path,switch)))
    table_id = sw["id"]
    command = {"id":self.last_id,
               "jsonrpc":"2.0",
               "method":"print_table",
               "params":{
                         "id":table_id
                         }
                 }
    return [command]
    
      