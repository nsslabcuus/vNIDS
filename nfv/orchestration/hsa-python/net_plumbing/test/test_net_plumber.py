'''
Created on Jun 26, 2012

@author: Peyman Kazemian
'''
import unittest
from utils.wildcard import *
from headerspace.hs import headerspace
from net_plumbing.net_plumber import NetPlumber

class Test(unittest.TestCase):


    def setUp(self):
      '''
      topology:
      box1: 1,2,3
      box2: 4,5,10
      box3: 6,7,11
      box4: 8,9,12
      2<-->4
      3<-->6
      5<-->8
      7<-->9
      box1: 
      (1010xxxx,1) --> (1010xxxx,2) 
      (10001xxx,1) --> (10000xxx,2)
      (10xxxxxx,[1,2]) --> (10xxxxxx,3)
      box2:
      (1011xxxx,4) --> (10101xxx,5) 
      (10xxxxxx,4) --> (111xxxxx,5) 
      box 3:
      (101xxxxx,[6,11]) --> (101xx111,7)
      box 4:
      (xxx010xx,8) --> (xxx010xx,12)
      
      '''
      self.N = NetPlumber(1)
      self.rule_ids = []
      self.N.add_link(2,4)
      self.N.add_link(4, 2)
      self.N.add_link(3, 6)
      self.N.add_link(6, 3)
      self.N.add_link(5, 8)
      self.N.add_link(8, 5)
      self.N.add_link(7, 9)
      self.N.add_link(9, 7)
      self.rule_ids.append(self.N.add_rule("B1", -1, [1], [2], \
                 wildcard_create_from_string("1010xxxx"), \
                 None, \
                 None))
      self.rule_ids.append(self.N.add_rule("B1", -1, [1], [2], \
                 wildcard_create_from_string("10001xxx"), \
                 None, \
                 None))
      self.rule_ids.append(self.N.add_rule("B1", -1, [1,2], [3], \
                  wildcard_create_from_string("10xxxxxx"), \
                  None, \
                  None))
      self.rule_ids.append(self.N.add_rule("B2", -1, [4], [5], \
                 wildcard_create_from_string("1011xxxx"), \
                 wildcard_create_from_string("11100111"), \
                 wildcard_create_from_string("00001000")))
      self.rule_ids.append(self.N.add_rule("B2", -1, [4], [5], \
                 wildcard_create_from_string("10xxxxxx"), \
                 wildcard_create_from_string("10011111"), \
                 wildcard_create_from_string("01100000")))
      self.rule_ids.append(self.N.add_rule("B3", -1, [6,11], [7], \
                 wildcard_create_from_string("101xxxxx"), \
                 wildcard_create_from_string("11111000"), \
                 wildcard_create_from_string("00000111")))
      self.rule_ids.append(self.N.add_rule("B4", -1, [8], [12], \
                 wildcard_create_from_string("xxx010xx"), \
                 None, \
                 None))


    def tearDown(self):
      pass


    def _checkPipelines(self,pipelines):
      for i in range(len(self.rule_ids)):
        r = self.N.node_by_id[self.rule_ids[i]] 
        self.assertEqual(len(r.next_in_pipeline),pipelines[i][0])
        self.assertEqual(len(r.previous_in_pipeline),pipelines[i][1])
        
    def _checkInfluencedBy(self,dependencies):
      for i in range(len(self.rule_ids)):
        r = self.N.node_by_id[self.rule_ids[i]] 
        self.assertEqual(len(r.affected_by),dependencies[i])

    def _checkSourceFlow(self,source_flows):
      for i in range(len(self.rule_ids)):
        r = self.N.node_by_id[self.rule_ids[i]] 
        d_count = 0
        i_count = 0
        for s_flow in r.source_flow:
          i_count += s_flow[0].count()
          d_count += s_flow[0].count_diff()
        self.assertEqual(i_count,source_flows[i][0])
        self.assertEqual(d_count,source_flows[i][1])  

    def testSetupPlumbing(self):
      dependencies = [0,0,2,0,1,0,0]
      pipelines = [(1,0),(1,0),(1,0),(1,0),(1,2),(0,1),(0,2)]
      source_flows = [(0,0),(0,0),(0,0),(0,0),(0,0),(0,0),(0,0)]
      self._checkInfluencedBy(dependencies)
      self._checkPipelines(pipelines)
      self._checkSourceFlow(source_flows)
      #self.N.print_pluming_network()
      
    def testRemoveRuleFromPlumbing(self):
      dependencies = [0,0,2,0,0,0]
      pipelines = [(0,0),(0,0),(1,0),(1,0),(0,1),(0,1)]
      self.N.remove_rule(self.rule_ids[4])
      self.rule_ids.remove(self.rule_ids[4])
      self._checkInfluencedBy(dependencies)
      self._checkPipelines(pipelines)
   
    def testAddSource(self):
      self.N.add_link(1, 100)
      self.N.add_link(100, 1)
      s = headerspace(1)
      s.add_hs(wildcard_create_from_string("1xxxxxxx"))
      self.N.add_source("client", s, [100])
      source_flows = [(1,0),(1,0),(1,2),(0,0),(2,0),(1,1),(2,0)]
      pipelines = [(1,1),(1,1),(1,1),(1,0),(1,2),(0,1),(0,2)]
      self._checkPipelines(pipelines)
      self._checkSourceFlow(source_flows)
      #self.N.print_pluming_network(True)
      
    def testRemoveSource(self):
      self.testAddSource()
      self.N.remove_source("client")
      #self.N.print_pluming_network(True)
      self.testSetupPlumbing()
      
    def testAddRemoveRule(self):
      # remove rule 4 and add a source and verify everything is correct
      self.N.remove_rule(self.rule_ids[4])
      self.rule_ids.remove(self.rule_ids[4])
      self.N.add_link(1, 100)
      self.N.add_link(100, 1)
      s = headerspace(1)
      s.add_hs(wildcard_create_from_string("1xxxxxxx"))
      self.N.add_source("client", s, [100])
      source_flows = [(1,0),(1,0),(1,2),(0,0),(1,1),(0,0)]
      pipelines = [(0,1),(0,1),(1,1),(1,0),(0,1),(0,1)]
      self._checkPipelines(pipelines)
      self._checkSourceFlow(source_flows)
      # Now adding back the same rule, verify things are correct
      self.rule_ids.append(self.N.add_rule("B2", -1, [4], [5], \
                 wildcard_create_from_string("10xxxxxx"), \
                 wildcard_create_from_string("10011111"), \
                 wildcard_create_from_string("01100000")))
      source_flows = [(1,0),(1,0),(1,2),(0,0),(1,1),(2,0),(2,0)]
      pipelines = [(1,1),(1,1),(1,1),(1,0),(0,1),(0,2),(1,2)]
      self._checkPipelines(pipelines)
      self._checkSourceFlow(source_flows) 
      
    def testAddRemoveLink(self):
      # test removing a link
      self.testAddSource()
      self.N.remove_link(2, 4)
      source_flows = [(1,0),(1,0),(1,2),(0,0),(0,0),(1,1),(0,0)]
      pipelines = [(0,1),(0,1),(1,1),(1,0),(1,0),(0,1),(0,2)]
      self.N.print_pluming_network(True)
      self._checkPipelines(pipelines)
      self._checkSourceFlow(source_flows)
      # test adding the link back
      self.N.add_link(2, 4)
      source_flows = [(1,0),(1,0),(1,2),(0,0),(2,0),(1,1),(2,0)]
      pipelines = [(1,1),(1,1),(1,1),(1,0),(1,2),(0,1),(0,2)]
      self.N.print_pluming_network(True)
      self._checkPipelines(pipelines)
      self._checkSourceFlow(source_flows)
      
    def testSourceReachabilityProbe(self):
      self.N.add_link(1, 100)
      self.N.add_link(100, 1)
      s = headerspace(1)
      s.add_hs(wildcard_create_from_string("1xxxxxxx"))
      self.N.add_source("client", s, [100])
      self.N.add_link(12, 200)
      self.N.add_link(200,12)
      self.N.add_source_reachability_probe("no-flow-from-client", [1], [200],\
                                      wildcard_create_from_string("xxxxxxxx"))
      probe_state = self.N.get_source_probe_state("no-flow-from-client")
      self.assertEqual(len(probe_state),2)
      #self.N.print_pluming_network(True)
      self.N.remove_source_reachability_probe("no-flow-from-client")
      self.N.remove_source("client")
      self.testSetupPlumbing()
      
    
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()