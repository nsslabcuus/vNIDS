'''
Created on Jul 11, 2012

@author: Peyman Kazemian
'''

from multiprocessing import Process
from utils.wildcard import wildcard_intersect


class set_influence_process(Process):
  
  def __init__(self,rule,dataQ,resultQ,sigterm):
    '''
    @rule: the rule to be set up.
    @dataQ: a Queue() object for receiving data from main thread. data should 
    be (other_rule, is_higher_priority)
    @sigterm: an Event() object to notify the thread to finish.
    '''
    Process.__init__(self)
    self.rule = rule
    self.dataQ = dataQ
    self.resultQ = resultQ
    self.sigterm = sigterm
    
  def run(self):
    while (not self.sigterm.is_set()):
      try:
        (r,is_higher_priority) = self.dataQ.get(False)
        common_ports = [val for val in r.input_ports 
                        if val in self.rule.input_ports]
        if len(common_ports) == 0:
          self.dataQ.task_done()
          continue
        common_headerspace = wildcard_intersect(self.rule.match, r.match)
        if len(common_headerspace) == 0:
          self.dataQ.task_done()
          continue
        self.resultQ.put((r.node_id,is_higher_priority,common_headerspace,common_ports))
        self.dataQ.task_done()
      except:
        pass
    self.resultQ.put(None)

class set_pipeline_process(Process):
  
  def __init__(self,rule,dataQ,resultQ,sigterm):
    '''
    @rule: the rule to be set up.
    @dataQ: a Queue() object for receiving data from main thread. data should 
    be (other_rule, self.rule's port, other_rule's port).
    @sigterm: an Event() object to notify the thread to finish.
    @mode: 0: forward, 1: reverse pipeline
    '''
    Process.__init__(self)
    self.rule = rule
    self.dataQ = dataQ
    self.resultQ = resultQ
    self.sigterm = sigterm
    
  def run(self):
    while (not self.sigterm.is_set()):
      try:
        (r,rule_port,r_port,back) = self.dataQ.get(False)
        if (back):
          survived_hs = wildcard_intersect(self.rule.match,r.inverse_match)
        else:
          survived_hs = wildcard_intersect(r.match,self.rule.inverse_match)
        if not survived_hs.is_empty():
          self.resultQ.put((survived_hs,r.node_id,rule_port,r_port,back))
        self.dataQ.task_done()
      except:
        pass
    self.resultQ.put(None)
      
class route_source_flow_process(Process):
  
  def __init__(self,taskQ,resultQ,sigterm):
    '''
    @rule: newly added rule
    '''
    Process.__init__(self)
    self.taskQ = taskQ
    self.resultQ = resultQ
    self.sigterm = sigterm
  
  def run(self):
    while (not self.sigterm.is_set()):
      try:
        (pipeline, s_flow) = self.taskQ.get(False)
        # if flow is going out from the port it comes from. ignore it.
        if (pipeline[2] == s_flow[1]):
          self.taskQ.task_done()
        else:
          f = s_flow[0].copy_intersect(pipeline[1])
          if f.count() > 0:
            new_source_flow = pipeline[0].process_source_flow(f,pipeline[3])
            self.resultQ.put((pipeline[0].node_id,new_source_flow))
            for next_pipeline in pipeline[0].next_in_pipeline:
              self.taskQ.put((next_pipeline,new_source_flow))
            self.taskQ.task_done()
          else:
            self.taskQ.task_done()
      except:
        pass
    self.resultQ.put(None)

