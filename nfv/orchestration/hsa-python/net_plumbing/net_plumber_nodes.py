'''
Created on Jun 26, 2012

@author: Peyman Kazemian
'''

from headerspace.hs import headerspace
from utils.wildcard import wildcard,wildcard_and, wildcard_or,wildcard_rewrite,\
wildcard_create_bit_repeat, wildcard_not
     
class Node(object):
  '''
  Basic class for all *Node objects.
  all subclasses should have these methods:
   - process_source_flow(self,input_port,hs):
  '''
  
  def __init__(self):
    self.node_id = ""  #a unique id for this node
    
    # Information about the source flows coming in and going out of this node
    # * source_flow: list of (output_hs, input_port).
    self.source_flow = []  
    
    # Information about the sink flows coming in and going out of this node
    # * sink_flow: list of (output_hs, input_port).
    self.sink_flow = []
    
    # Information about connection of this rule with other rules in the network
    # * next_in_pipleine: list of (RuleNode,headerspace,port) where RuleNode is 
    # next rule in pipeline and headerspace is a wildcard representing maximum 
    # HS reaching to it. Port is connecting port.
    # * previous_in_pipeline: similar to next_in_pipeline, but for the reverse
    # direction
    self.next_in_pipeline = []
    self.previous_in_pipeline = []
    
    self.input_ports = []
    self.output_ports = []
    self.match = None
    self.inverse_match = None
        
  def set_next_in_pipeline(self,node,common_headerspace,from_port,to_port):
    '''
    @node: next node in pipeline that can process this rule's output.
    @common_headerspace: wildcard representing common headerspace of the rules
    @from_port,@to_port: the common port between the rules
    '''
    self.next_in_pipeline.append((node,common_headerspace,from_port,to_port))
    return self

  def set_previous_in_pipeline(self,node,common_headerspace,from_port,to_port):
    '''
    @node: previous node in pipeline that might have processed
               this rule's input.
    @common_headerspace: wildcard representing common headerspace of the rules
    @from_port,@to_port: the common port between the rules
    '''
    self.previous_in_pipeline.append((node,common_headerspace,from_port,\
                                      to_port))
    return self
  
  def pipelines_to(self,node):
    for pipeline in self.next_in_pipeline:
      if (pipeline[0] == node):
        yield pipeline

  def pipelines_from(self,node):
    for pipeline in self.previous_in_pipeline:
      if (pipeline[0] == node):
        yield pipeline
  
  def process_source_flow(self,hs,input_port):
    '''
    @hs: the headerspace reached this node and should be processed
    @input_port: is the port the flow has come from.
    @return a list of headerspace objects stored in source_flow as a result
    of this processing
    '''
    raise Exception("process_source_flow(port,hs) is not implemented")
  
  def remove_source_flow_through_node(self,node_id):
    '''
    removes all source_flows coming from rule and recursively remove it from 
    next rules in pipeline.
    '''
    seenHS = False
    for i in reversed(range(len(self.source_flow))):
      s_flow = self.source_flow[i]
      for applied_rule in s_flow[0].applied_rules:
        if applied_rule[1] == node_id:
          self.source_flow.remove(s_flow)
          seenHS = True
          break
    return seenHS
  
  def remove_source_flow_through_port(self,port):
    seenHS = False
    for i in reversed(range(len(self.source_flow))):
      s_flow = self.source_flow[i]
      for applied_rule in s_flow[0].applied_rules:
        if applied_rule[2] == port:
          self.source_flow.remove(s_flow)
          seenHS = True
          break
    return seenHS
  
  
class RuleNode(Node):
  '''
  A rule in the network plumbing graph.
  Note: the rule will steal the ref to all inputs
  '''

  def __init__(self):
    '''
    Constructor
    '''
    Node.__init__(self)
    
    # Information about the table to which this rule belongs
    self.table = ""  #the name of the table that this rule belongs to.
    
    # Basic information about the rule itself. similar to rule in tf.py
    self.mask = None
    self.rewrite = None
    self.inverse_rewrite = None
    
    # Information about higher priority rules that affect this rule
    # list of (RuleNode,common_headerspace,common_ports)
    self.affected_by = []
    
    # Information about lower priority rules that are affected by this rule
    # list of RuleNode
    self.influence_on = [] 
    
    
  def set_rule(self,table,in_ports,out_ports,match,mask,rewrite):
    '''
    sets the essential infomation about a rule and automatically computes 
    inverse match and rewrite.
    '''
    self.input_ports = in_ports
    self.output_ports = out_ports
    self.match = match
    self.mask = mask
    self.rewrite = rewrite
    self.table = table
    if (mask.__class__ == wildcard and rewrite.__class__ == wildcard):
      masked = wildcard_and(match, mask)
      rewritten = wildcard_or(masked, rewrite)
      self.inverse_match = rewritten
      self.inverse_rewrite = wildcard_and(wildcard_not(mask), match)
    else:
      self.mask = None
      self.rewrite = None
      self.inverse_match = match
      self.inverse_rewrite = None
    return self
  
  @property
  def rule_id(self):
    return self.node_id
  
  def _set_node_id(self,value):
    self.node_id = value
      
  def affected_by_rule(self,ruleNode,common_headerspace,common_ports):
    '''
    @ruleNode: RuleNode affected by this rule
    @common_headerspace: bytearray representing common headerspace of the rules
    @common_ports: a list of ports common between the rules
    '''
    self.affected_by.append((ruleNode,common_headerspace,common_ports))
    return self
  
  def influenced_on_rule(self,ruleNode):
    '''
    @ruleNode: the RuleNode influenced by this rule.
    '''
    self.influence_on.append(ruleNode)
    return self
  
  
  def process_source_flow(self,hs,input_port):
    '''
    process hs according to ruleNode and return the resulting new source flow.
    If no hs resulted, return None
    '''
    # subtract off all the higher priority matches
    for (r,com_h,com_ports) in self.affected_by:
      if input_port in com_ports:
        hs.diff_hs(com_h)
    hs.clean_up()
    if (hs.count() == 0):
      return None
    
    # rewrite if this is a rewrite rule
    if self.mask != None and self.rewrite != None:
      for i in range(0,len(hs.hs_list)):
        (rew,card) = wildcard_rewrite(hs.hs_list[i],self.mask,self.rewrite)
        hs.hs_list[i] = rew
        new_diff_list = []
        for diff_hs in hs.hs_diff[i]:
          (diff_rew,diff_card) = wildcard_rewrite(diff_hs,\
                                                  self.mask,\
                                                  self.rewrite)
          if diff_card == card:
            new_diff_list.append(diff_rew)
            hs.hs_diff[i] = new_diff_list

    # add this rule to the rule history of hs and also put hs is source flow.
    for applied_rule in hs.applied_rules:
      if applied_rule[1] == self.node_id:
        print "LOOP DETECTED"
        return None
    hs.push_applied_tf_rule(None,self.node_id,input_port)
    new_source_flow = (hs,input_port)
    self.source_flow.append(new_source_flow)
    return new_source_flow
    
class SourceNode(Node):
  ''' 
  a node in the network plumbing graph that can generate flow from the 
  connecting point.
  Note: the rule will steal the ref to all inputs
  '''
  def __init__(self,name,hs,ports,length):
    '''
    @name: a unique name for this source node 
    '''
    Node.__init__(self)
    self.node_id = name
    self.output_ports = ports
    self.input_ports = []
    hs.push_applied_tf_rule(None, self.node_id, None)
    self.source_flow.append((hs,None))
    self.match = wildcard_create_bit_repeat(length,0x3)
    self.inverse_match = wildcard_create_bit_repeat(length,0x3)
  
  @property
  def source_name(self):
    return self.node_id
  
  def _set_node_id(self,value):
    self.node_id = value
    
class SinkNode(Node):
  ''' 
  a node in the network plumbing graph which activates all flows toward the
  connecting point.
  '''
  def __init__(self):
    Node.__init__(self)
    self.sink_headerspace = None  #headerspace() that it can absorve
    self.sink_ports = [] #set of ports this is connected to
  
class ProbeNode(Node):
  ''' 
  a node in the network plumbing graph that can check contraints on the 
  flow passed through it.
  '''
  def __init__(self,probes_result):
    Node.__init__(self)
    self.probes_results = probes_result
    
  def get_violating_flows(self):
    return self.probes_results[self.node_id]
  
  def remove_source_flow_through_node(self,node_id):
    seenHS = False
    for i in reversed(range(len(self.source_flow))):
      s_flow = self.source_flow[i]
      for applied_rule in s_flow[0].applied_rules:
        if applied_rule[1] == node_id:
          self.source_flow.remove(s_flow)
          if s_flow in self.probes_results[self.node_id]:
            self.probes_results[self.node_id].remove(s_flow) 
          seenHS = True
          break
    return seenHS
  
  def remove_source_flow_through_port(self,port):
    seenHS = False
    for i in reversed(range(len(self.source_flow))):
      s_flow = self.source_flow[i]
      for applied_rule in s_flow[0].applied_rules:
        if applied_rule[2] == port:
          self.source_flow.remove(s_flow)
          if s_flow in self.probes_results[self.node_id]:
            self.probes_results[self.node_id].remove(s_flow) 
          seenHS = True
          break
    return seenHS
  
  def is_violated(self):
    return (len(self.probes_results[self.node_id]) == 0)
      
    
class SourceReachabilityProbeNode(ProbeNode):
  
  def __init__(self,probe_name,probes_result,probe_ports,\
               constraint_ports,constraint_wc):
    '''
    @probes_result: global dictionary for collecting probe results. 
    @probe_ports: list of ports this is connected to.
    @constraint_ports: list of ports that if the receiving hs has ever passed on
    them will fire the probe.
    @constraint_wc: a wildcard rule for set of header spaces to watch for.
    '''
    ProbeNode.__init__(self, probes_result)
    self.node_id = probe_name
    self.constraint_ports = constraint_ports
    self.output_ports = []
    self.input_ports = probe_ports
    self.match = constraint_wc
    self.inverse_match = None
    
  def process_source_flow(self,hs,input_port):
    new_source_flow = (hs,input_port)
    for applied_rule in hs.applied_rules:
      if applied_rule[2] in self.constraint_ports:
        self.probes_results[self.node_id].append(new_source_flow)
        break
    self.source_flow.append(new_source_flow)
    return None
  
  
  