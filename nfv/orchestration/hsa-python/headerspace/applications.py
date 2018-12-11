'''
    <Reachability and Loop detection applications -- Part of HSA Library>
    Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
    a special exception, as described in included LICENSE_EXCEPTION.txt.
    
Created on Jan 27, 2011

@author: Peyman Kazemian
'''
from headerspace.hs import headerspace
from utils.wildcard import wildcard_create_bit_repeat

def print_p_node(p_node):
    print "-----"
    print p_node["hdr"]
    print p_node["port"]
    print p_node["visits"]
    print "-----"

def find_reachability(NTF, TTF, in_port, out_ports,input_pkt):
    paths = []
    propagation = []
 
    p_node = {}
    p_node["hdr"] = input_pkt
    p_node["port"] = in_port
    p_node["visits"] = []
    p_node["hs_history"] = []
    propagation.append(p_node)
    loop_count = 0
    while len(propagation)>0:
        #get the next node in propagation graph and apply it to NTF and TTF
        print "Propagation has length: %d"%len(propagation)
        tmp_propagate = []
        print "loops: %d"%loop_count
        for p_node in propagation:
            next_hp = NTF.T(p_node["hdr"],p_node["port"])
            for (next_h,next_ps) in next_hp:
                for next_p in next_ps:
                    if next_p in out_ports:
                        reached = {}
                        reached["hdr"] = next_h
                        reached["port"] = next_p
                        reached["visits"] = list(p_node["visits"])
                        reached["visits"].append(p_node["port"])
                        reached["hs_history"] = list(p_node["hs_history"])
                        paths.append(reached)
                    else:
                        linked = TTF.T(next_h,next_p)
                        for (linked_h,linked_ports) in linked:
                            for linked_p in linked_ports:
                                new_p_node = {}
                                new_p_node["hdr"] = linked_h
                                new_p_node["port"] = linked_p
                                new_p_node["visits"] = list(p_node["visits"])
                                new_p_node["visits"].append(p_node["port"])
                                #new_p_node["visits"].append(next_p)
                                new_p_node["hs_history"] = list(p_node["hs_history"])
                                new_p_node["hs_history"].append(p_node["hdr"])
                                if linked_p in out_ports:
                                    paths.append(new_p_node)
                                elif linked_p in new_p_node["visits"]:
                                    loop_count += 1
                                    #print "WARNING: detected a loop - branch aborted: \nHeaderSpace: %s\n Visited Ports: %s\nLast Port %d "%(\
                                    #    new_p_node["hdr"],new_p_node["visits"],new_p_node["port"])
                                else:
                                    tmp_propagate.append(new_p_node)
        propagation = tmp_propagate
                
    return paths
                    
def detect_loop(NTF, TTF, ports, test_packet = None, out_port_offset = 0):
    loops = []
    for port in ports:
        print "port %d is being checked"%port
        propagation = []
        
        # put all-x test packet in propagation graph
        test_pkt = test_packet
        if test_pkt == None:
            all_x = wildcard_create_bit_repeat(NTF.length,0x3)
            test_pkt = headerspace(NTF.length)
            test_pkt.add_hs(all_x)
        
        p_node = {}
        p_node["hdr"] = test_pkt
        p_node["port"] = port
        p_node["visits"] = []
        p_node["hs_history"] = []
        
        propagation.append(p_node)
        while len(propagation)>0:
            #get the next node in propagation graph and apply it to NTF and TTF
            print "Propagation has length: %d"%len(propagation)
            tmp_propag = []
            for p_node in propagation:
                next_hp = NTF.T(p_node["hdr"],p_node["port"])
                for (next_h,next_ps) in next_hp:
                    for next_p in next_ps:
                        linked = TTF.T(next_h,next_p)
                        for (linked_h,linked_ports) in linked:
                            for linked_p in linked_ports:
                                new_p_node = {}
                                new_p_node["hdr"] = linked_h
                                new_p_node["port"] = linked_p
                                new_p_node["visits"] = list(p_node["visits"])
                                new_p_node["visits"].append(p_node["port"])
                                #new_p_node["visits"].append(next_p)
                                new_p_node["hs_history"] = list(p_node["hs_history"])
                                new_p_node["hs_history"].append(p_node["hdr"])
                                #print new_p_node
                                if len(new_p_node["visits"]) > 0 and new_p_node["visits"][0] == linked_p:
                                    loops.append(new_p_node)
                                    print "loop detected"
                                elif linked_p in new_p_node["visits"] or (linked_p + out_port_offset) in new_p_node["visits"]:
                                    pass
                                else:
                                    tmp_propag.append(new_p_node)
            propagation = tmp_propag
    return loops
        
def print_paths(paths, reverse_map):
    for p_node in paths:
        #p_node["hdr"].self_diff()
        #if (p_node["hdr"].is_empty()):
            #continue
        print "----------------------------------------------"
        str = ""
        for port in p_node["visits"]:
            if str == "":
                str = reverse_map["%d"%port]
            else:
                str = "%s ---> %s"%(str,reverse_map["%d"%port])
        str = "%s ---> %s"%(str,reverse_map["%d"%p_node["port"]])
        print "Path: %s"%str
        rl_id =  "applied rules: "
        for (n,r,s) in p_node["hdr"].applied_rules:
            rl_id = rl_id + " -> %s"%r
        print rl_id
        for i in range(len(p_node["hs_history"])):
            print "*** %d) AT PORT: %s\nHS: %s\n"%(i,reverse_map["%d"%p_node["visits"][i]],p_node["hs_history"][i])
        print "*** %d) AT PORT: %s\nHS: %s\n"%(i+1,reverse_map["%d"%p_node["port"]],p_node["hdr"])
        print "----------------------------------------------"
        
        
def loop_path_to_str(p_node, reverse_map):
    str = ""
    for port in p_node["visits"]:
        if str == "":
            str = reverse_map["%d"%port]
        else:
            str = "%s ---> %s"%(str,reverse_map["%d"%port])
    str = "%s ---> %s"%(str,reverse_map["%d"%p_node["port"]])
    return str
        
def trace_hs_back(applied_rule_list,hs,last_port):

    port = last_port
    hs_list = [hs]
    hs.applied_rule_ids = []
    for (tf,rule_id,in_port) in reversed(applied_rule_list):
        tmp = []
        for next_hs in hs_list:
            hp = tf.T_inv_rule(rule_id,next_hs,port)
            for (h,p_list) in hp:
                if in_port in p_list:
                    tmp.append(h)
        if tmp == []:
            break
        hs_list = tmp
        port = in_port
    return hs_list
        
        
def find_original_header(NTF,TTF,propagation_node):
    applied_rules = list(propagation_node["hdr"].applied_rules)
    hs_list = trace_hs_back(applied_rules,propagation_node["hdr"],propagation_node["port"])
    return hs_list
        
