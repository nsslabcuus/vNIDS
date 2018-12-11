'''
Created on Jun 26, 2012

@author: Peyman Kazemian
'''
from utils.wildcard import *
from net_plumbing.net_plumber import NetPlumber
from headerspace.hs import headerspace
from time import time
from random import choice

def generate_random_wc():
  r = ["1","0","x"]
  result = ""
  for i in range(8):
    sym = choice(r)
    result += sym
  return result

if __name__ == '__main__':
  N = NetPlumber(1)
  rule_ids = []
  N.add_link(2,4)
  N.add_link(4, 2)
  N.add_link(3, 6)
  N.add_link(6, 3)
  N.add_link(5, 8)
  N.add_link(8, 5)
  N.add_link(7, 9)
  N.add_link(9, 7)
  N.add_link(1, 100)
  N.add_link(100, 1)
  s = headerspace(1)
  s.add_hs(wildcard_create_from_string("1xxxxxxx"))
  N.add_source("client", s, [100])
  st = time()
  rule_ids.append(N.add_rule("B1", -1, [1], [2], \
                 wildcard_create_from_string("1010xxxx"), \
                 None, \
                 None))
  en = time()
  print "time ",en-st
  st = time()
  rule_ids.append(N.add_rule("B1", -1, [1], [2], \
                 wildcard_create_from_string("10001xxx"), \
                 None, \
                 None))
  en = time()
  print "time ",en-st
  st = time()
  rule_ids.append(N.add_rule("B1", -1, [1,2], [3], \
                  wildcard_create_from_string("10xxxxxx"), \
                  None, \
                  None))
  en = time()
  print "time ",en-st
  st = time()
  rule_ids.append(N.add_rule("B2", -1, [4], [5], \
                 wildcard_create_from_string("1011xxxx"), \
                 wildcard_create_from_string("11100111"), \
                 wildcard_create_from_string("00001000")))
  en = time()
  print "time ",en-st
  st = time()
  rule_ids.append(N.add_rule("B2", -1, [4], [5], \
                 wildcard_create_from_string("10xxxxxx"), \
                 wildcard_create_from_string("10011111"), \
                 wildcard_create_from_string("01100000")))
  en = time()
  print "time ",en-st
  st = time()
  rule_ids.append(N.add_rule("B3", -1, [6,11], [7], \
                 wildcard_create_from_string("101xxxxx"), \
                 wildcard_create_from_string("11111000"), \
                 wildcard_create_from_string("00000111")))
  en = time()
  print "time ",en-st
  st = time()
  rule_ids.append(N.add_rule("B4", -1, [8], [12], \
                 wildcard_create_from_string("xxx010xx"), \
                 None, \
                 None))
  en = time()
  print "time ",en-st
  master_st = time()
  for i in range(1000):
    mtch = generate_random_wc()
    st = time()
    rule_ids.append(N.add_rule("B2", -1, [4], [5], \
                 wildcard_create_from_string(mtch), \
                 None, \
                 None))
    en = time()
    #if (en-st > 0.1):
    print mtch, " at B2 takes ",(en-st)
    
  for i in range(1000):
    mtch = generate_random_wc()
    st = time()
    rule_ids.append(N.add_rule("B1", -1, [8], [12], \
                 wildcard_create_from_string(mtch), \
                 None, \
                 None))
    en = time()
    #if (en-st > 0.1):
    print mtch, " at B1 takes ",(en-st)
    
  for i in range(1000):
    mtch = generate_random_wc()
    st = time()
    rule_ids.append(N.add_rule("B4", -1, [1], [2], \
                 wildcard_create_from_string(mtch), \
                 None, \
                 None))
    en = time()
    #if (en-st > 0.01):
    print mtch, " at B4 takes ",(en-st)
  master_en = time()
  print "master time ",(master_en-master_st)
  
  #N.print_pluming_network(True)