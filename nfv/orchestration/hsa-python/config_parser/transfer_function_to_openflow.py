'''
  <Converts transfer function object to a set of equivalent OpenFlow rules -- Part of HSA Library>
  
  Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
  a special exception, as described in included LICENSE_EXCEPTION.txt.
  
Created on Mar 27, 2012

@author: Peyman Kazemian
'''
import json
from utils.helper import int_to_dotted_ip
from utils.wildcard import wildcard_and,wildcard_or,wildcard_create_bit_repeat
from headerspace.tf import TF

class OpenFlow_Rule_Generator(object):
  
  def __init__(self,tf,hs_format):
    '''
    hs_format could have the following fields:
    POSITION FIELDS: mac_src_pos, mac_dst_pos, vlan_pos, ip_src_pos, ip_dst_pos, ip_proto_pos, transport_src_pos, transport_dst_pos
    LENGTH FIELDS: mac_src_len, mac_dst_len, vlan_len, ip_src_len, ip_dst_len, ip_proto_len, transport_src_len, transport_dst_len
    '''
    self.hs_format = hs_format
    self.tf = tf
  
  def parse_non_wc_field(self,field,right_wc):
    '''
    right_wc can be True for IP fields and False for non-IP fields. 
    It indicates if this field should be treated as a right-hand masked 
    field or not.
    '''
    
    wildcards = []
    if right_wc:
      found_right_wc = -1
    else:
      found_right_wc = 0
    value = 0
    for i in range (len(field)):
      for j in range (8):
        next_bit = (field[i] >> (2*j)) & 0x03
        if right_wc and found_right_wc == -1 and next_bit != 0x03:
          # detect when we have scanned all right wildcarded bits
          found_right_wc = j + i*8
          
        if next_bit == 0x02 and found_right_wc != -1:
          value += (2**(j + i*8))
 
    return (value,found_right_wc)
  
  def find_new_field(self,field_match,field_mask,field_rewrite):
    '''
    finds out the new value for this field. If it is unknown 
    (i.e. there are wildcard bits in it), returns None.
    '''
    all_masked = True
    for i in range (len(field_mask)):
      if (field_mask[i] != 0xaaaa):
        all_masked = False
    if (all_masked):
      return None
    
    rw = wildcard_or(\
                      wildcard_and(field_match,field_mask),\
                      field_rewrite)

    try:
      value = int(rw.__str__(0).replace(",", ""),2)
      return value
    except:
      print "ERROR: Unexpected rewrite action. Ignored. %s - %s - %s - %s"%\
      (field_match,field_mask,field_rewrite,rw)
      return None
  
  def parse_rule(self,rule):
    '''
    Parses a single rule and generate openflow entry for that rule.
    the resulting openflow entry will have this format:
    FIEDL_wc: if the field is not wildcarded (0) or wildcarded (1) for IP fields, this a number between 0-32
    counting number of wildcarded bits from right
    FIELD_match: the match value for this field, after applying appropriate wildcard.
    FIELD_new: in case of a rewrite action, the new field value to be rewritten.
    '''
    fields = ["mac_src", "mac_dst", "vlan", "ip_src", "ip_dst", "ip_proto", "transport_src", "transport_dst"]
    openflow_entry = {}
    for field in fields:
      if "%s_pos"%field not in self.hs_format.keys():
        continue
      
      position = self.hs_format["%s_pos"%field]
      l = self.hs_format["%s_len"%field]
      wildcarded = True
      field_match = wildcard_create_bit_repeat(l,0x1)
      field_mask = wildcard_create_bit_repeat(l,0x1)
      field_rewrite = wildcard_create_bit_repeat(l,0x1)
      for i in range(l):
        field_match[i] = rule["match"][position+i]
        if rule["mask"] != None:
          field_mask[i] = rule["mask"][position+i]
          field_rewrite[i] = rule["rewrite"][position+i]
        if field_match[i] != 0xffff:
          wildcarded = False

      if wildcarded:
        if field == "ip_src" or field == "ip_dst":
          openflow_entry["%s_wc"%field] = 32
        else:
          openflow_entry["%s_wc"%field] = 1
        openflow_entry["%s_match"%field] = 0
      else:
        if field == "ip_src" or field == "ip_dst":
          parsed = self.parse_non_wc_field(field_match, True)
        else:
          parsed = self.parse_non_wc_field(field_match, False)
        openflow_entry["%s_wc"%field] = parsed[1]
        openflow_entry["%s_match"%field] = parsed[0]
        
      if (rule["mask"] != None):
        openflow_entry["%s_new"%field] = self.find_new_field(\
                                          field_match,field_mask,field_rewrite)
      else:
        openflow_entry["%s_new"%field] = None
        
      openflow_entry["in_ports"] = rule["in_ports"]
      openflow_entry["out_ports"] = rule["out_ports"]
    
    return openflow_entry
  
  @staticmethod
  def pretify(of_rule):
    fields = ["mac_src", "mac_dst", "vlan", "ip_src", "ip_dst", "ip_proto", "transport_src", "transport_dst"]
    wc_val = [1,1,1,32,32,1,1,1]
    match = ""
    rewrite = ""
    for i in range(len(fields)):
      field = fields[i]
      if "%s_wc"%field in of_rule.keys() and of_rule["%s_wc"%field] != wc_val[i]:
        if field == "ip_src" or field == "ip_dst":
          match = "%s%s=%s/%d,"%(match,field,
                                 int_to_dotted_ip(of_rule["%s_match"%field]),
                                 32-of_rule["%s_wc"%field])
        else:
          match = "%s%s=%s,"%(match,field,of_rule["%s_match"%field])
      if "%s_new"%field in of_rule.keys() and of_rule["%s_new"%field] != None:
        if field == "ip_src" or field == "ip_dst":
          rewrite = "%s%s=%s,"%(rewrite,field,
                                 int_to_dotted_ip(of_rule["%s_new"%field]))
        else:
          rewrite = "%s%s=%s,"%(rewrite,field,of_rule["%s_new"%field])
    if rewrite != "":
      rewrite = "Rewrite:%s;"%rewrite[:-1]
    if match == "":
      match = "Match:all;"
    else:
      match = "Match:%s;"%match[:-1]
      
    return (match,rewrite)
  
  def generate_of_rules(self,filename):
    f = open(filename,'w')
    rules = []
    for rule in self.tf.rules:
      of_rule = self.parse_rule(rule)
      rules.append(of_rule)
      
    f.write("{\"rules\":")
    f.write(json.dumps(rules))
    f.write("}")
    f.close()
      
