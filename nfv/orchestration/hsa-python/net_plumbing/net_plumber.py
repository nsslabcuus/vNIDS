'''
Created on Jun 25, 2012

@author: Peyman Kazemian
'''
from headerspace.hs import headerspace
from net_plumbing.net_plumber_nodes import RuleNode, SourceNode, SinkNode,\
ProbeNode,SourceReachabilityProbeNode
from net_plumbing.net_plumber_process import *
from multiprocessing import cpu_count, Event, JoinableQueue as jQueue
from utils.wildcard import wildcard_intersect

NUM_THREADS = 1#2*cpu_count() - 1

class NetPlumber(object):
    '''
    This class maintains a live, up-to-date view of network and the interaction
    between rules installed in the network.
    '''

    def __init__(self, header_length):
      '''
      Constructor
      '''
      # length: L parameter in HSA
      self.length = header_length  
      
      # topology: a dictionary from sourePort (string) to a list of destination 
      # ports (to allow one to many links)
      self.topology = {}  
      self.inv_topology = {}
      
      # Information about rules and tables in this network 
      # * tables: a dictionary mapping the table names to rules in the table
      # in an ordered list
      # * node_by_id: a dictionary mapping node_id to rules
      self.tables = {}
      self.sources = {}
      self.probes = {}
      self.node_by_id = {}
      self.last_id_used_for_table = {}
      
      # inport_to_node: input-port to node dictionary.
      self.inport_to_node = {}
      
      # outport_to_node: output-port to node dictionary map. 
      self.outport_to_node = {}

      # global collector of all source probe node results      
      self.source_probes_result = {}
      
    def get_source_probe_state(self,name=None):
      if (name == None):
        return self.source_probes_result
      elif name in self.source_probes_result.keys():
        return self.source_probes_result[name]
      else:
        return None
      
    def add_link(self, sPort, dPort):
      '''
      adds a link to the topology of network from sPort to dPort.
      '''
      if "%d" % sPort in self.topology.keys():
        self.topology["%d" % sPort].append(dPort)
      else:
        self.topology["%d" % sPort] = [dPort]
      if "%d" % dPort in self.inv_topology.keys():
        self.inv_topology["%d" % dPort].append(sPort)
      else:
        self.inv_topology["%d" % dPort] = [sPort]
      self.__update_plumber_for_new_link(sPort, dPort)
        
    def remove_link(self, sPort, dPort):
      '''
      removes the link between sPort and dPort (unidirectional), if exist.
      '''
      if sPort in self.topology.keys():
        if dPort in self.topology["%d" % sPort]:
          self.topology["%d" % sPort].remove(dPort)
      if dPort in self.inv_topology.keys():
        if sPort in self.inv_topology["%d" % dPort]:
          self.inv_topology["%d" % dPort].remove(sPort)
      self.__update_plumber_for_removed_link(sPort, dPort)
      
      
    def get_dst_end_of_link(self, port):
      '''
      returns the list of port numbers at the dst end of link
      '''
      if "%d" % port not in self.topology.keys():
        return []
      else:
        return self.topology["%d" % port]

    def get_src_end_of_link(self, port):
      '''
      returns the list of port numbers at the src end of link
      '''
      if "%d" % port not in self.inv_topology.keys():
        return []
      else:
        return self.inv_topology["%d" % port]
      
    def get_topology(self):
      '''
      for debuging.
      returns a list of (sPort,[dPort]) pairs.
      '''
      results = []
      for sPort in self.topology.keys():
        results.append((int(sPort), self.topology[sPort]))
      return results
      
    def add_source(self, name, hs, ports):
      '''
      adds a source node named @name generating flow of @hs at @ports.
      @hs: headerspace() object.
      @ports: list of port numbers
      '''
      if name in self.node_by_id.keys():
        return False
      
      s = SourceNode(name, hs, ports, hs.length)
      # set up outport_to_node pointers
      for port in ports:
        if str(port) not in self.outport_to_node.keys():
          self.outport_to_node[str(port)] = []
        self.outport_to_node[str(port)].append(s)
      self.node_by_id[name] = s
      self.sources[name] = s
      #set up pipeline dependencies
      self.__set_pipeline_dependencies(s)
      #route source flow
      self.__route_source_flow(s)
      # TODO: route sink flow
          
    def remove_source(self,name):
      '''
      remove source node named @name from the network
      '''
      if name not in self.sources.keys():
        return False
      s = self.node_by_id[name]
      
      #clear pipelines
      self.__remove_next_in_pipeline(s)
        
      #remove source flows from network
      self.__remove_source_flows_through_node(s,s.node_id)
        
      #remove the source from the dics
      for port in s.output_ports:
        self.outport_to_node[str(port)].remove(s)
      self.node_by_id.pop(name)
      self.sources.pop(name)
      
    def add_rule(self, table, index, in_ports, out_ports, match, mask, rewrite):
      '''
      @table: table name
      @index: position in table
      @in_ports: list of input ports to match on.
      @out_ports: list of output ports to send to
      @match: matching headerspace for this rule.
      @mask: mask pattern (or None). should have 0 on all bits to be rewritten.
      @rewrite: rewrite pattern. should rewrite only un-masked places.
      '''
      r = RuleNode().set_rule(table, in_ports, out_ports, \
                             match, mask, rewrite)
      
      # If this is first time a rule added to this table, initialize it.
      if table not in self.tables.keys():
        self.tables[table] = []
        self.last_id_used_for_table[table] = 0
      
      # Update inport and outport lookup maps
      for port in in_ports:
        if str(port) not in self.inport_to_node.keys():
          self.inport_to_node[str(port)] = []
        self.inport_to_node[str(port)].append(r)
      for port in out_ports:
        if str(port) not in self.outport_to_node.keys():
          self.outport_to_node[str(port)] = []
        self.outport_to_node[str(port)].append(r)        
      
      # generate unique id for this rule
      new_id = self.last_id_used_for_table[table] + 1
      rule_id = "%s_%d" % (table, new_id)
      self.last_id_used_for_table[table] = new_id
      r._set_node_id(rule_id)
      
      # add this rule to the correct table in tables map
      if index < 0 or len(self.tables[table]) <= index:
        self.tables[table].append(r)
      else:
        self.tables[table].insert(index, r)
      
      # add this rule to node_by_id map
      self.node_by_id[rule_id] = r
      
      # setup table dependency
      self.__set_influences(r)
      
      # setup pipeline dependency
      self.__set_pipeline_dependencies(r)
      
      # route source flow through this node
      self.__route_source_flow(r)
      
      #TODO route sink flow
      
      return rule_id
      
    def remove_rule(self, rule_id):
      '''
      removes the rule with id=@node_id from the network.
      '''
      if rule_id not in self.node_by_id.keys():
        return False
      
      #clear influence_on and affected_by
      rule = self.node_by_id[rule_id]
      for r in rule.influence_on:
        for i in reversed(range(len(r.affected_by))):
          a = r.affected_by[i]
          if a[0] == rule:
            r.affected_by.remove(a)
      for a in rule.affected_by:
        a[0].influence_on.remove(rule)
        
      #clear pipelines
      self.__remove_next_in_pipeline(rule)
      self.__remove_previous_pipeline(rule)
        
      #remove source flow
      self.__remove_source_flows_through_node(rule,rule.node_id)
      
      #TODO: remove sink flow
        
      #remove the rule from the tables, node_by_id and inport/outport_to_node
      for port in rule.input_ports:
        self.inport_to_node[str(port)].remove(rule)
      for port in rule.output_ports:
        self.outport_to_node[str(port)].remove(rule)
      self.tables[rule.table].remove(rule)
      self.node_by_id.pop(rule_id)
      return True
        
    def add_source_reachability_probe(self,probe_name,from_ports,to_ports,wc):
      if probe_name in self.node_by_id.keys():
        return False
      
      self.source_probes_result[probe_name] = []
      p = SourceReachabilityProbeNode(probe_name,self.source_probes_result,\
                                      to_ports,from_ports,wc)
      for port in to_ports:
        if str(port) not in self.outport_to_node.keys():
          self.outport_to_node[str(port)] = []
        self.outport_to_node[str(port)].append(p)
      self.probes[probe_name] = p
      self.node_by_id[probe_name] = p
      
      #set up pipeline dependencies
      self.__set_pipeline_dependencies(p)
      #route source flow
      self.__route_source_flow(p)
    
    def remove_source_reachability_probe(self,probe_id):
      if probe_id not in self.probes.keys():
        return False
      p = self.node_by_id[probe_id]
      
      #clear pipeline
      self.__remove_previous_pipeline(p)
      
      # clear port and id look-ups
      for port in p.output_ports:
        self.outport_to_node[str(port)].remove(p)
      self.source_probes_result.pop(probe_id)
      self.probes.pop(probe_id)
      self.node_by_id.pop(probe_id)
      
    def print_pluming_network(self, print_flow=False):
      '''
      For debuging purposes
      '''
      for table in self.tables.keys():
        print "*" * 20
        print "table: %s" % table
        print "*" * 20
        for rule in self.tables[table]:
          print "Rule: %s (match: %s, in_ports = %s, mask: %s, rewrite: %s, out_ports: %s)"%\
          (rule.node_id, rule.match, rule.input_ports, \
          rule.mask, rule.rewrite, rule.output_ports)
          print "Pipelined To:"
          for (r, wc, f_port,t_port) in rule.next_in_pipeline:
            print "\t%s (%s,%d --> %d)" % (r.node_id, wc, f_port,t_port)
          print "Pipelined From:"
          for (r, wc, f_port, t_port) in rule.previous_in_pipeline:
            print "\t%s (%s,%d --> %d)" % (r.node_id, wc, f_port, t_port)
          print "Affected By:"
          for (r, wc, ports) in rule.affected_by:
            print "\t%s (%s,%s)" % (r.node_id, wc, ports)
          if (print_flow):
            print "Source Flow:"
            for s_flow in rule.source_flow:
              print "  From port %d:"%s_flow[1]
              lines = str(s_flow[0]).split("\n")
              for line in lines:
                print "\t",line
          print "==" * 10
      for sname in self.sources.keys():
        s = self.sources[sname]
        print "*" * 20
        print "source: %s" % s.source_name
        print "*" * 20
        print "Pipelined To:"
        for (r,wc,f_port,t_port) in s.next_in_pipeline:
          print "\t%s (%s,%d --> %d)" % (r.node_id, wc, f_port, t_port)
        if (print_flow):
          print "Source Flow:"
          for s_flow in s.source_flow:
              print "\t%s"%(s_flow[0])
      for pname in self.probes:
        p = self.probes[pname]
        print "*" * 20
        print "probe: %s" % p.node_id
        print "*" * 20
        print "Pipelined From:"
        for (r, wc, f_port, t_port) in p.previous_in_pipeline:
          print "\t%s (%s,%d --> %d)" % (r.node_id, wc, f_port, t_port)
        if (print_flow):
          print "Source Flow:"
          for s_flow in p.source_flow:
            print "  From port %d:"%s_flow[1]
            lines = str(s_flow[0]).split("\n")
            for line in lines:
              print "\t",line
        print "Violations:"
        for s_flow in p.probes_results[p.node_id]:
          path = ""
          for applied_rule in s_flow[0].applied_rules:
            path += "(%s, @p=%s)"%(applied_rule[1],str(applied_rule[2])) + "-->"
          path += "(Probe, @p=%d)"%(s_flow[1])
          print "  Path: %s"%path
          print "  Header at Destination:"
          lines = str(s_flow[0]).split("\n")
          for line in lines:
            print "\t",line
      
      
    def __get_rules_by_input_port(self, port):
      if "%d" % port in self.inport_to_node.keys():
        return self.inport_to_node["%d" % port]
      else:
        return []
      
    def __get_rules_by_output_port(self, port):
      if "%d" % port in self.outport_to_node.keys():
        return self.outport_to_node["%d" % port]
      else:
        return []
    
    def __set_influences(self,rule):
      higher_priority = True
      table = rule.table
      for r in self.tables[table]:
        if rule.node_id == r.node_id:
          higher_priority = False
        else:
          common_ports = [val for val in r.input_ports 
                          if val in rule.input_ports]
          if len(common_ports) == 0:
              continue
          common_headerspace = wildcard_intersect(rule.match, r.match)
          if len(common_headerspace) == 0:
            continue
          if (higher_priority):
            r.influenced_on_rule(rule)
            rule.affected_by_rule(r, common_headerspace, common_ports)
          else:
            rule.influenced_on_rule(r)
            r.affected_by_rule(rule, common_headerspace, common_ports)
      
    def __set_pipeline_dependencies(self, node):
      for port in node.output_ports:
        next_ports = self.get_dst_end_of_link(port)
        for next_port in next_ports:
          potential_next_rules = self.__get_rules_by_input_port(next_port)
          for r in potential_next_rules:
            survived_hs = wildcard_intersect(r.match,node.inverse_match)
            if not survived_hs.is_empty():
              node.set_next_in_pipeline(r,survived_hs,port,next_port)
              r.set_previous_in_pipeline(node,survived_hs,next_port,port)
              
      for port in node.input_ports:
        previous_ports = self.get_src_end_of_link(port)
        for previous_port in previous_ports: 
          potential_back_rules = self.__get_rules_by_output_port(previous_port)
          for r in potential_back_rules:
            survived_hs = wildcard_intersect(node.match,r.inverse_match)
            if not survived_hs.is_empty():
              r.set_next_in_pipeline(node,survived_hs,previous_port,port)
              node.set_previous_in_pipeline(r,survived_hs,port,previous_port)
      
    def __update_plumber_for_new_link(self,sPort,dPort):
      source_routing_tasks = []
      potential_src_rules = self.__get_rules_by_output_port(sPort)
      potential_dest_rules = self.__get_rules_by_input_port(dPort)
      for s_rule in potential_src_rules:
        for d_rule in potential_dest_rules:
          survived_hs = wildcard_intersect(d_rule.match,s_rule.inverse_match)
          if not survived_hs.is_empty():
            s_rule.set_next_in_pipeline(d_rule,survived_hs,sPort,dPort)
            d_rule.set_previous_in_pipeline(s_rule,survived_hs,dPort,sPort)
            fwd_pipeline = s_rule.next_in_pipeline[-1]
            for src_flow in s_rule.source_flow:
              source_routing_tasks.append((fwd_pipeline,src_flow))
      self.__perform_source_routing_tasks(source_routing_tasks)
      
    def __route_source_flow(self, node):
      tasks = []
      if node.__class__ == SourceNode:
        for pipeline in node.next_in_pipeline:
          tasks.append((pipeline,node.source_flow[0]))
      elif node.__class__ == RuleNode or issubclass(node.__class__,ProbeNode):
        for (r,h,p1,p2) in node.previous_in_pipeline:
          for pipeline in r.pipelines_to(node):
            for s_flow in r.source_flow:
              tasks.append((pipeline,s_flow))
      self.__perform_source_routing_tasks(tasks)
              
    def __perform_source_routing_tasks(self, tasks):
      while len(tasks) > 0:
        (pipeline,s_flow) = tasks.pop()
        if (pipeline[2] == s_flow[1]):
          continue
        else:
          f = s_flow[0].copy_intersect(pipeline[1])
          if f.count() > 0:
            new_source_flow = pipeline[0].process_source_flow(f,pipeline[3])
            if new_source_flow == None:
              continue
            for next_pipeline in pipeline[0].next_in_pipeline:
              tasks.append((next_pipeline,new_source_flow))
              
    def __remove_source_flows_through_node(self,node,node_id):
      seenHS = node.remove_source_flow_through_node(node_id)
      if (seenHS):
        for pipeline in node.next_in_pipeline:
          self.__remove_source_flows_through_node(pipeline[0], node_id)
          
    def __remove_source_flow_through_port(self,node,port):
      seenHS = node.remove_source_flow_through_port(port)
      if (seenHS):
        for pipeline in node.next_in_pipeline:
          self.__remove_source_flow_through_port(pipeline[0], port)
        
            
    def __update_plumber_for_removed_link(self,sPort,dPort):
      potential_src_rules = self.__get_rules_by_output_port(sPort)
      potential_dest_rules = self.__get_rules_by_input_port(dPort)
      for s_rule in potential_src_rules:
        for i in reversed(range(len(s_rule.next_in_pipeline))):
          fwd_pipeline = s_rule.next_in_pipeline[i]
          if fwd_pipeline[2] == sPort and fwd_pipeline[3] == dPort:
            self.__remove_source_flow_through_port(fwd_pipeline[0], dPort)
            s_rule.next_in_pipeline.remove(fwd_pipeline)
      for d_rule in potential_dest_rules:
        for i in reversed(range(len(d_rule.previous_in_pipeline))):
          rev_pipeline = d_rule.previous_in_pipeline[i]
          if rev_pipeline[2] == dPort and rev_pipeline[3] == sPort:
            #TODO: remove sink flow
            d_rule.previous_in_pipeline.remove(rev_pipeline)
        
    def __remove_previous_pipeline(self,node):
      for pp in node.previous_in_pipeline:
        prev_node_next_in_pipeline = pp[0].next_in_pipeline
        for i in reversed(range(len(prev_node_next_in_pipeline))):
          np = prev_node_next_in_pipeline[i]
          if np[0] == node:
            prev_node_next_in_pipeline.remove(np)
            
    def __remove_next_in_pipeline(self,node):
      for np in node.next_in_pipeline:
        next_node_previous_in_pipeline = np[0].previous_in_pipeline
        for i in reversed(range(len(next_node_previous_in_pipeline))):
          pp = next_node_previous_in_pipeline[i]
          if pp[0] == node:
            next_node_previous_in_pipeline.remove(pp)

      
    '''
    Experimental
    '''
    def __set_influences_mp(self, rule):
      '''
      adds influence of all higher ranked rules to @rule.
      add influence of @rule to all lower ranked rules.  
      @rule is newly added rule
      '''
      #setting up threads
      dataQ = jQueue()
      resultQ = jQueue()
      sigterm = Event()
      processess = []
      for i in range(NUM_THREADS):
        p = set_influence_process(rule,dataQ,resultQ,sigterm)
        processess.append(p)
        p.start()
        
      table = rule.table
      higherPriority = True
      for r in self.tables[table]:
        if rule.node_id == r.node_id:
          higherPriority = False
        else:
          dataQ.put((r,higherPriority))
      
      #waiting for threads to be done.
      dataQ.join()
      sigterm.set()
      count = NUM_THREADS
      while (count > 0):
        next_result = resultQ.get()
        if next_result == None:
          count -= 1
          continue
        (rule_id,higher_priority,com_hs,com_ports) = next_result
        r = self.node_by_id[rule_id]
        if (higher_priority):
          r.influenced_on_rule(rule)
          rule.affected_by_rule(r, com_hs, com_ports)
        else:
          rule.influenced_on_rule(r)
          r.affected_by_rule(rule, com_hs, com_ports)
          
      for p in processess:
        p.join()
        
    def __set_pipeline_dependencies_mp(self, rule):
      '''
      @rule is newly added rule
      '''
      #setting up threads
      dataQ = jQueue()
      resultQ = jQueue()
      sigterm = Event()
      processess = []
      for i in range(NUM_THREADS):
        p = set_pipeline_process(rule,dataQ,resultQ,sigterm)
        processess.append(p)
        p.start()
      
      for port in rule.output_ports:
        next_ports = self.get_dst_end_of_link(port)
        for next_port in next_ports:
          potential_next_rules = self.__get_rules_by_input_port(next_port)
          for r in potential_next_rules:
            dataQ.put((r,port,next_port,False))
      for port in rule.input_ports:
        previous_ports = self.get_src_end_of_link(port)
        for previous_port in previous_ports: 
          potential_back_rules = self.__get_rules_by_output_port(previous_port)
          for r in potential_back_rules:
            dataQ.put((r,port,previous_port,True))
            
      dataQ.join()
      sigterm.set()
      count = NUM_THREADS
      while (count > 0):
        next_result = resultQ.get()
        if next_result == None:
          count -= 1
          continue
        (survived_hs,node_id,rule_port,r_port,back) = next_result
        r = self.node_by_id[node_id]
        if (back):
          r.set_next_in_pipeline(rule,survived_hs,r_port,rule_port)
          rule.set_previous_in_pipeline(r,survived_hs,rule_port,r_port)
        else:
          rule.set_next_in_pipeline(r,survived_hs,rule_port,r_port)
          r.set_previous_in_pipeline(rule,survived_hs,r_port,rule_port)

      for p in processess:
        p.join()
        
    def __route_source_flow_mp(self, rule):
      '''
      Note: node should already have all the pipeline and influence states 
      set up before calling this method.
      @rule: the rule for which we want to route flow
      '''
      # taskQ: a queue of tasks.
      # each task is (prev_rule_pipeline_to_rule, source_flow).
      # source_flow should be routed from prev_rule to rule
      print "route source flow"
      taskQ = jQueue()
      resultQ = jQueue()
      # create thread
      processess = []
      sigterm = Event()
      for i in range(NUM_THREADS):
        p = route_source_flow_process(taskQ,resultQ,sigterm)
        processess.append(p)
        p.start()
        
      if rule.__class__ == SourceNode:
        for pipeline in rule.next_in_pipeline:
          taskQ.put((pipeline,rule.source_flow[0]))
      elif rule.__class__ == RuleNode:
        for (r,h,p1,p2) in rule.previous_in_pipeline:
          for pipeline in r.pipelines_to(rule):
            for s_flow in r.source_flow:
              taskQ.put((pipeline,s_flow))
      
      taskQ.join()
      sigterm.set()
      count = NUM_THREADS
      while (count > 0):
        next_result = resultQ.get()
        if next_result == None:
          count -= 1
          continue
        (node_id,new_source_flow) = next_result
        r = self.node_by_id[node_id]
        r.source_flow.append(new_source_flow)
        
      for p in processess:
        p.join()
      print "end: route source flow"
