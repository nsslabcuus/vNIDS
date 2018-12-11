'''
  <emulates the functionality of multi-table boxes using one transfer 
  function -- Part of HSA Library>
  
  Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
  a special exception, as described in included LICENSE_EXCEPTION.txt.
  
Created on Aug 14, 2011

@author: Peyman Kazemian
'''
class emulated_tf(object):
  
  def __init__(self,n_reapet,duplicate_removal=True):
    self.switch_id_mul = 100000
    self.port_type_mul = 10000
    self.output_port_const = 2
    # list of transfer functions emulated by this class
    self.tf_list = []
    self.num_repeat = n_reapet
    # which stage of TF is FWD engine. starting from 0
    self.fwd_engine_stage = 1
    self.length = 0
    self.duplicate_removal = duplicate_removal
    
  def set_fwd_engine_stage(self,stage):
    self.fwd_engine_stage = stage
    
  def set_multipliers(self,switch_id_mul,port_type_mul,output_port_const):
    self.switch_id_mul = switch_id_mul
    self.port_type_mul = port_type_mul
    self.output_port_const = output_port_const
    
  def append_tf(self,tf):
    self.tf_list.append(tf)
    self.length = tf.length
    
  def insert_tf_at(self,tf,pos):
    self.tf_list.insert(pos, tf)
    
  def remove_duplicates(self,input_hs_list):
    '''
    try to find duplicates based on applied fwd-engine-stage rules
    '''
    hs_buckets = {}
    to_be_removed = []
    for input_index in range(len(input_hs_list)):
      (cur_hs,cur_ports) = input_hs_list[input_index]
      bucket_name = "%s_%s"%(cur_hs.applied_rules[len(cur_hs.applied_rules) - \
                        self.num_repeat + self.fwd_engine_stage -1],cur_ports)
      if bucket_name not in hs_buckets.keys():
        hs_buckets[bucket_name] = [input_index]
      else:
        renew_bucket = []
        for i in hs_buckets[bucket_name]:
          prev_hs = input_hs_list[i][0]
          if prev_hs.is_contained_in(cur_hs):
            to_be_removed.append(i)
          else:
            renew_bucket.append(i)
        renew_bucket.append(input_index)
        hs_buckets[bucket_name] = renew_bucket
        
    to_be_removed.sort(cmp=None, key=None, reverse=True)
    for i in to_be_removed:
      input_hs_list.pop(i)
        
  def T(self,hs,port):
    sw_id = port / self.switch_id_mul - 1
    if sw_id >= len(self.tf_list):
      return []
    tf = self.tf_list[sw_id]
    phase = [(hs,[port])]
    for i in range(0,self.num_repeat):
      tmp = []
      for (hs,port_list) in phase:
        for p in port_list:
          tmp.extend(tf.T(hs,p))
      phase = tmp
    # 1) remove output port that is the same as input. 2)remove duplicates
    result = []
    for (h,ports) in phase:
      if port + self.output_port_const * self.port_type_mul in ports:
        ports.remove(port + self.output_port_const * self.port_type_mul)
      if (len(ports)>0):
        result.append((h,ports))  
    if self.duplicate_removal:
      self.remove_duplicates(result)
      
    return result 
  
  def T_inv(self,hs,port):
    sw_id = port / self.switch_id_mul - 1
    if sw_id >= len(self.tf_list):
      return []
    tf = self.tf_list[sw_id]
    phase = [(hs,[port])]
    for i in range(0,self.num_repeat):
      tmp = []
      for (hs,port_list) in phase:
        for p in port_list:
          tmp.extend(tf.T_inv(hs,p))
      phase = tmp
    return phase

    
