'''
Created on Sep 8, 2012

@author: peymankazemian
'''
from utils.helper import dotted_subnet_to_int, mac_to_int, dotted_ip_to_int, l2_proto_to_int
from utils.wildcard_utils import set_header_field
from utils.wildcard import wildcard, wildcard_create_bit_repeat, wildcard_to_str
import json

class WildcardTypeEncoder(json.JSONEncoder):
  def default(self, obj):
    if isinstance(obj, wildcard):
      return wildcard_to_str(obj)
    return json.JSONEncoder.default(self, obj)

class OFProtobufParser(object):
  
  def __init__(self):
    self.flows = {}
    self.multipath = {}
    self.ports = {}
    self.ports["onix:controller(of_port_name)"] = True
    self.port_members = {}
    self.topology = {}
    self.port_map = {}
    self.next_port_id = {}
    self.switch_ids = {}
    self.switch_counter = 0
    self.SWITCH_ID_MULTIPLIER = 100000
    self.PORT_TYPE_MULTIPLIER = 10000
    '''
    self.format = {"dl_src_pos":0, "dl_dst_pos":6, "dl_type_pos":12,
                   "nw_src_pos":14, "nw_dst_pos":18, "nw_tos_pos":22,
                   "dl_src_len":6, "dl_dst_len":6, "dl_type_len":2,
                   "nw_src_len":4, "nw_dst_len":4, "nw_tos_len":1,
                   "length":23
                   }
    '''
    self.format = {"nw_src_pos":0, "nw_dst_pos":4, "dl_type_pos":8, "nw_tos_pos":10,
                   "nw_src_len":4, "nw_dst_len":4, "dl_type_len":2, "nw_tos_len":1,
                   "length":11
                   }    
  
  def __parse_action(self,action):
    actions_str = action.strip("[]").split(",")
    actions = {}
    for action_str in actions_str:
      action_str = action_str.strip()
      if action_str.startswith("OUTPUT to port"):
        actions["output"] = action_str[len("OUTPUT to port "):]
      elif action_str.startswith("SET DL SRC to"):
        #actions["set_dl_src"] = action_str[len("SET DL SRC to "):]
        pass
      elif action_str.startswith("SET DL DST to"):
        #actions["set_dl_dst"] = action_str[len("SET DL DST to "):]
        pass
      elif action_str.startswith("SET NW SRC to"):
        actions["set_nw_src"] = action_str[len("SET NW SRC to "):]
      elif action_str.startswith("SET NW DST to"):
        actions["set_nw_dst"] = action_str[len("SET NW DST to "):]
      elif action_str.startswith("Pop IP"):
        actions["pop_ip"] = ""
      elif action_str.startswith("Push IP"):
        actions["push_ip"] = ""
    return actions
      
  def __parse_flow_match(self,flow_match):
    parts = flow_match.split(" ")
    match = wildcard_create_bit_repeat(self.format["length"],3)
    num_fields = 0
    for part in parts:
      if not part.startswith("priority") and part != "":
        fv = part.split("=")
        field = fv[0]
        value = fv[1]
        if field == "dl_src" or field=="dl_dst":
          '''
          m = mac_to_int(value)
          if m != 0:
            set_header_field(self.format, match, field, m, 0)
          '''
          pass
        elif field == "nw_src" or field == "nw_dst":
          num_fields += 1
          (ip,subnet) = dotted_subnet_to_int(value)
          set_header_field(self.format, match, field, ip, 32-subnet)
        elif field == "nw_tos":
          num_fields += 1
          set_header_field(self.format, match, field, int(value), 0)
        elif field == "dl_type":
          num_fields += 1
          set_header_field(self.format, match, field, l2_proto_to_int(value), 0)
    if num_fields > 0:
      return match
    else:
      return None
        
  def __process_topo_entry(self,name,members,enabled):
    if len(members) > 0:
      self.port_members[name] = members
    else:
      if name in self.ports:
        self.ports[name] = (self.ports[name] or enabled)
      else:
        self.ports[name] = enabled
  
  def __encode_port_list(self, ports, rtr):
    result = []
    for port in ports:
      parts = port.split(":")
      if len(parts) > 1 and self.ports[port] == True:
        result.append(self.get_port_id(parts[0], parts[1]))
      else:
        result.append(self.get_port_id(rtr, port))
    return result
  
  def __compress_port_list(self, lst):
    #print "port linst initial: ",lst
    final_list = []
    sws = set()
    for port in lst:
      parts = (port.split(":"))
      sw = parts[0]
      p = parts[1]
      if port in self.topology:
        dst_port = self.topology[port]
      else:
        dst_port = port
      if sw not in sws and self.ports[port] and self.ports[dst_port]:
        sws.add(sw)
        final_list.append(port)
    #print "port list final: ",final_list
    return final_list
    
  def __expand_mport(self,rtr,mport):
    mport_rules = self.multipath[rtr][mport]
    result = []
    for mport_rule in mport_rules:
      if "encap" in mport_rule or "decap" in mport_rule:
        pass
      elif "output" in mport_rule:
        result.append(mport_rule["output"])
    return result
      
  
  def __add_action_to_rule(self,action,rule,rtr):
    #print "Action:", action, " Rule: ",rule
    mask = wildcard_create_bit_repeat(self.format["length"],2)
    rewrite = wildcard_create_bit_repeat(self.format["length"],1)
    out_ports = []
    rw = False
    push = False
    pop = False
    for operation in action.keys():
      if operation == "set_nw_src" or operation == "set_nw_dst":
        rw = True
        set_header_field(self.format, mask, operation[4:], 0, 0)
        set_header_field(self.format, rewrite, operation[4:], dotted_ip_to_int(action[operation]), 0)
      elif operation == "set_dl_src" or operation == "set_dl_dst":
        rw = True
        set_header_field(self.format, mask, operation[4:], 0, 0)
        set_header_field(self.format, rewrite, operation[4:], mac_to_int(action[operation]), 0)
      elif operation == "output":
        '''
        if action[operation] in self.port_members:
          out_ports = self.__encode_port_list(self.port_members[action[operation]],rtr)
        else:
        '''
        if action[operation].startswith("mport"):
          out_ports = self.__expand_mport(rtr, action[operation])
        else:
          out_ports = [action[operation]]
        out_ports = self.__compress_port_list(out_ports)
        out_ports = self.__encode_port_list(out_ports, rtr)
      elif operation == "push_ip":
        push = True
        rule["encap_pos"] = self.format["nw_src_pos"]
        rule["encap_len"] = 8
      elif operation == "pop_ip":
        pop = True
        rule["decap_pos"] = self.format["nw_src_pos"]
        rule["decap_len"] = 8
    rule["out_ports"] = out_ports
    if push:
      rule["action"] = "encap"
      rule["mask"] = mask
      rule["rewrite"] = rewrite
    elif pop:
      rule["action"] = "decap"
      rule["mask"] = None
      rule["rewrite"] = None
    elif rw:
      rule["action"] = "rw"
      rule["mask"] = mask
      rule["rewrite"] = rewrite
    else:
      rule["action"] = "fwd"
      rule["mask"] = None
      rule["rewrite"] = None
  
  def __generate_mp_tf_rules(self, rtr):
    result_rules = []
    for mp in self.multipath[rtr]:
      group_rule = {"action":"multipath","rules":[]}
      rule = {}
      rule["in_ports"] = [self.get_port_id(rtr, mp)+self.PORT_TYPE_MULTIPLIER]
      rule["match"] = wildcard_create_bit_repeat(self.format["length"],3)
      is_fwd_action = True
      for single_action in self.multipath[rtr][mp]:
        rule_copy = rule.copy()
        self.__add_action_to_rule(single_action,rule_copy,rtr)
        if (rule_copy["action"] != "fwd"):
          is_fwd_action = False
        group_rule["rules"].append(rule_copy)
      if (is_fwd_action):
        all_out_ports = []
        for g_rule in group_rule["rules"]:
          all_out_ports.extend(g_rule["out_ports"])
        s = set(all_out_ports)
        rule["out_ports"] = self.__compress_port_list(list(s))
        rule["action"] = "fwd"
        rule["mask"] = None
        rule["rewrite"] = None
        group_rule["rules"] = [rule]
        result_rules.append(group_rule)
      else:
        result_rules.append(group_rule)
    return result_rules
  
  def __generate_tf_rules(self,rtr):
    result_rules = []
    for flow in self.flows[rtr]:
      if flow["match"] == None:
        continue
      rule = {}
      rule["match"] = flow["match"]
      rule["in_ports"] = []
      rule["priority"] = flow["priority"]
      self.__add_action_to_rule(flow["action"],rule,rtr)
      result_rules.append(rule)
    sorted(result_rules,key=lambda elem: elem["priority"])
    return result_rules
      
  def __generate_topology(self):
    topo = {"topology":[]}
    # add trk ports to self.ports
    for port in self.port_members:
      for member in self.port_members[port]:
        if self.ports[member]:
          self.ports[port] = True
          break
      if port not in self.ports:
        self.ports[port] = False
        
    for src_port in self.topology:
      dst_port = self.topology[src_port]
      if self.ports[src_port] and self.ports[dst_port]:
        print "connection: ",src_port," --> ",dst_port
        parts = src_port.split(":")
        src_id = self.get_port_id(parts[0], parts[1])
        parts = dst_port.split(":")
        dst_id = self.get_port_id(parts[0], parts[1])
        topo["topology"].append({"src":src_id,"dst":dst_id})
    '''
    for rtr in self.multipath:
      for port in self.multipath[rtr]:
        port_id = self.get_port_id(rtr, port)
        topo["topology"].append({"src":port_id,"dst":port_id+self.PORT_TYPE_MULTIPLIER})
    '''
    return topo
        
  def read_flows_ascii(self,filename):
    f = open(filename,'r')
    last_name_seen = ""
    flow_match = ""
    flow_actions = ""
    priority = 0
    for next_line in f:
      line = next_line.strip()
      if line.startswith("entity_description"):
        last_name_seen = ""
        
      if last_name_seen == "" and line.startswith("name"):
        last_name_seen = line.split("\"")[1]
        self.flows[last_name_seen] = []
      elif last_name_seen != "":
        if line.startswith("flow_match"):
          flow_match = (line.split("\"")[1]).strip("[]")
        elif line.startswith("priority"):
          priority = int((line.split(":")[1]).strip())
        elif line.startswith("flow_actions"):
          flow_actions = line.split("\"")[1]
          actions = self.__parse_action(flow_actions)
          match = self.__parse_flow_match(flow_match)
          self.flows[last_name_seen].append({"match":match,
                                             "action":actions,
                                             "priority":priority})

  
  def read_flows_binary(self,filename):
    pass
  
  def read_multipath_ascii(self,filename):
    f = open(filename,'r')
    last_name_seen = ""
    last_port_seen = ""
    for next_line in f:
      line = next_line.strip()
      if line.startswith("entity_description"):
        last_name_seen = ""
        
      if last_name_seen == "" and line.startswith("name"):
        last_name_seen = line.split("\"")[1]
        self.multipath[last_name_seen] = {}
      elif last_name_seen != "":
        if line.startswith("name"):
          last_port_seen = line.split("\"")[1]
          self.multipath[last_name_seen][last_port_seen] = []
        elif line.startswith("actions"):
          action_buckets = line.split("\"")[1]
          actions = self.__parse_action(action_buckets)
          self.multipath[last_name_seen][last_port_seen].append(actions)
        
  def read_multipath_binary(self,filename):
    pass
  
  def read_topology_ascii(self,filename):
    f = open(filename,'r')
    seen_node_groups = False
    last_port_seen = ""
    member_ports = []
    enabled = False
    seen_link_groups = False
    src_port_seen = False
    dst_port_seen = False
    src_port = ""
    dst_port = ""
    for next_line in f:
      line = next_line.strip()
      
      if line.startswith("ports") or line.startswith("interfaces"):
        last_port_seen = ""
        member_ports = []
      elif line.startswith("node_groups"):
        seen_node_groups = True
      elif seen_node_groups and line.startswith("name"):
        seen_node_groups = False
      elif line.startswith("link_groups"):
        seen_link_groups = True

        
      if (seen_link_groups):
        if line.startswith("src_port"):
          src_port_seen = True
        elif line.startswith("dst_port"):
          dst_port_seen = True
        elif line.startswith("name") and src_port_seen:
          src_port_seen = False
          src_port = line.split("\"")[1]
        elif line.startswith("name") and dst_port_seen:
          dst_port_seen = False
          dst_port = line.split("\"")[1]
          self.topology[src_port] = dst_port
      else:
        if not seen_node_groups and last_port_seen == "" and line.startswith("name"):
          last_port_seen = line.split("\"")[1]
        elif last_port_seen != "" and line.startswith("name"):
          member_ports.append(line.split("\"")[1])
        elif last_port_seen != "" and line.startswith("enabled"):
          en = (line.split(":")[1]).strip()
          enabled = (en == "true")
          self.__process_topo_entry(last_port_seen, member_ports, enabled)

  def read_topology_binary(self,filename):
    pass
  
  def genearte_port_map(self):
    port_list = self.ports.keys()
    port_list.extend(self.port_members.keys())
    for port in port_list:
      parts = port.split(":")
      if parts[0] not in self.port_map:
        self.port_map[parts[0]] = {}
        self.switch_counter += 1
        self.switch_ids[parts[0]] = self.switch_counter
        self.next_port_id[parts[0]] = self.SWITCH_ID_MULTIPLIER * self.switch_counter
      if parts[1] not in self.port_map[parts[0]]:
        self.next_port_id[parts[0]] += 1
        self.port_map[parts[0]][parts[1]] = self.next_port_id[parts[0]]
    '''
    for rtr in self.multipath.keys():
      for m_port in self.multipath[rtr].keys():
        self.next_port_id[rtr] += 1
        self.port_map[rtr][m_port] = self.next_port_id[rtr]
    ''' 
  def get_port_id(self, rtr, port):
    if rtr in self.port_map:
      if port in self.port_map[rtr]:
        return self.port_map[rtr][port]
    return 0
  
  def get_port_name_by_id(self,port):
    parts = port.split(":")
    return self.get_port_id(parts[0], parts[1])
  
  def generate_tf(self,output_path):
    pass
  
  def generate_rules(self,output_path):
    total = len(self.flows)
    count = 0
    topo = self.__generate_topology()
    f = open("%s/topology.json"%(output_path), 'w')
    f.write(json.dumps(topo, indent=1))
    f.close()
    print "topology saved to file topology.json (",len(topo["topology"])," links)."
    f = open("%s/port_map.json"%(output_path), 'w')
    f.write(json.dumps(self.port_map, indent=1))
    f.close()   
    for rtr in self.flows:
      rtr_ports = []
      for port in self.port_map[rtr]:
        if not port.startswith("mport"):
          rtr_ports.append(self.port_map[rtr][port])
      f = open("%s/%s.rules.json"%(output_path,rtr), 'w')
      rules = self.__generate_tf_rules(rtr)
      tf = {"rules":rules, "length":self.format["length"], "ports":rtr_ports, "id":self.switch_ids[rtr]*10}
      f.write(json.dumps(tf, indent=1, cls=WildcardTypeEncoder))
      f.close()
      count += 1
      print "generated transfer function for router ",rtr,". (",count,"/",total,")"
    '''
    total = len(self.multipath)
    count = 0
    for rtr in self.multipath:
      rtr_ports = []
      for port in self.port_map[rtr]:
        if not port.startswith("mport"):
          rtr_ports.append(self.port_map[rtr][port])
      f = open("%s/%s.mp.rules.json"%(output_path,rtr), 'w')
      rules = self.__generate_mp_tf_rules(rtr)
      tf = {"rules":rules, "ports":rtr_ports, "length":self.format["length"], "id":self.switch_ids[rtr]*10+1}
      f.write(json.dumps(tf, indent=1, cls=WildcardTypeEncoder))
      f.close()
      count += 1
      print "generated multipath transfer function for router ",rtr,". (",count,"/",total,")"
      '''
      
  def generate_graph_file(self, output_path):
    f = open("%s/graph.json"%(output_path), 'w')
    s = set()
    graph = {"links":[], "nodes":[]}
    links = []
    for src_port in self.topology:
      dst_port = self.topology[src_port]
      if (src_port in self.ports) and (dst_port in self.ports):
        if self.ports[src_port] and self.ports[dst_port]:
          parts = src_port.split(":")
          src_id = int(self.get_port_id(parts[0], parts[1]) / self.SWITCH_ID_MULTIPLIER)
          parts = dst_port.split(":") 
          dst_id = int(self.get_port_id(parts[0], parts[1]) / self.SWITCH_ID_MULTIPLIER)
          s.add(src_id)
          s.add(dst_id)
          links.append( {"source":src_id, "target":dst_id} )
    nodes = list(s)
    for link in links:
      graph["links"].append({"source":nodes.index(link["source"]),"target":nodes.index(link["target"])})
    for node in nodes:
      graph["nodes"].append({"name":str(node)})
    f.write(json.dumps(graph, indent=1))
          
    
