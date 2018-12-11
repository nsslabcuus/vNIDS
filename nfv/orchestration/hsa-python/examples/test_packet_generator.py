'''
    <>

    Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
    a special exception, as described in included LICENSE_EXCEPTION.txt.
    
Generate Test Packets

@author: James Hongyi Zeng
'''
from examples.load_stanford_backbone import *
from headerspace.applications import *
from headerspace.hs import *
from multiprocessing import Pool, cpu_count
import time, sqlite3

ntf_global = ""
ttf_global = ""
src_port_ids_global = set()
dst_port_ids_global = set()

DATABASE_FILE = "results/db.sqlite"
TABLE_TEST_PACKETS = "test_packets"
TABLE_TEST_PACKETS_GLOBALLY_COMPRESSED = "test_packets_globally_compressed"
TABLE_TEST_PACKETS_LOCALLY_COMPRESSED = "test_packets_locally_compressed"
CPU_COUNT = cpu_count()

port_reverse_map_global = {}
port_map_global = {}

def find_reachability_test(NTF, TTF, in_port, out_ports, input_pkt):
    paths = []
    propagation = []
 
    p_node = {}
    p_node["hdr"] = input_pkt
    p_node["port"] = in_port
    p_node["visits"] = []
    #p_node["hs_history"] = []
    propagation.append(p_node)
    #loop_count = 0
    while len(propagation) > 0:
        #get the next node in propagation graph and apply it to NTF and TTF
        #print "Propagation has length: %d"%len(propagation)
        tmp_propagate = []
        for p_node in propagation:
            next_hp = NTF.T(p_node["hdr"], p_node["port"])
            for (next_h, next_ps) in next_hp:            
                for next_p in next_ps:
                    new_p_node = {}
                    new_p_node["hdr"] = next_h
                    new_p_node["port"] = next_p
                    new_p_node["visits"] = list(p_node["visits"])
                    new_p_node["visits"].append(p_node["port"])
                    #new_p_node["hs_history"] = list(p_node["hs_history"])
                    
                    linked = TTF.T(next_h, next_p)
                    
                    # Reached an edge port
                    if (linked == []):
                        if next_p in out_ports:
                            paths.append(new_p_node)
                    
                    for (linked_h, linked_ports) in linked:
                        for linked_p in linked_ports:
                            new_p_node = {}
                            new_p_node["hdr"] = linked_h
                            new_p_node["port"] = linked_p
                            new_p_node["visits"] = list(p_node["visits"])
                            new_p_node["visits"].append(p_node["port"])
                            #new_p_node["hs_history"] = list(p_node["hs_history"])
                            #new_p_node["hs_history"].append(p_node["hdr"])
                            if linked_p not in new_p_node["visits"]:
                                tmp_propagate.append(new_p_node)
                                
        propagation = tmp_propagate
                
    return paths

def print_paths_to_database(paths, reverse_map, table_name):
    # Timeout = 6000s
    conn = sqlite3.connect(DATABASE_FILE, 6000)
    
    for p_node in paths:
        path_string = ""
        for port in p_node["visits"]:
            path_string += ("%d " % port)
        path_string += ("%d " % p_node["port"])
        port_count = len(p_node["visits"]) + 1
        
        rl_id = ""
        for (n, r, s) in p_node["hdr"].applied_rule_ids:
            rl_id += (r + " ")
        rule_count = len(p_node["hdr"].applied_rule_ids)
        
        input_port = p_node["visits"][0]
        output_port = p_node["port"]
        header_string = byte_array_to_pretty_hs_string(p_node["hdr"].hs_list[0])
        
        insert_string = "INSERT INTO %s VALUES (?, ?, ?, ?, ?, ?, ?)" % table_name
        conn.execute(insert_string, (header_string, input_port, output_port, path_string, port_count, rl_id, rule_count))
        
    conn.commit()
    conn.close()

def path_compress(paths):
    ''' Compress Paths using Greedy Algorithm
    An implementation based on Min-Set-Cover
    '''
    # Step 1: Merge all rules
    rule_lists = []
    
    rule_ids_set = set()
    for i in xrange(0, len(paths)):
        p_node = paths[i]
        rule_lists.append([])
        for (n, r, s) in p_node["hdr"].applied_rule_ids:
            rule_ids_set.add(r)
            rule_lists[i].append(r)
            
    # Step 2: Greedy Algorithm
    result_rule_lists = []
    result_paths = []
    while(len(rule_ids_set) > 0):
        max_score = 0
        max_score_index = 0
        for i in xrange(0, len(rule_lists)):
            rule_list = rule_lists[i]
            score = 0
            for r in rule_list:
                if r in rule_ids_set:
                    score += 1
            if score > max_score:
                max_score = score
                max_score_index = i
        
        max_score_rule_list = rule_lists[max_score_index]
        result_paths.append(paths[max_score_index])
        result_rule_lists.append(max_score_rule_list)
        
        # Rules that have been hit already
        rule_ids_set -= set(max_score_rule_list)
        del rule_lists[max_score_index]
        del paths[max_score_index]
    
    return result_paths


def rule_lists_compress(rule_lists):
    rule_ids_set = set()
    for rule_list in rule_lists:
        rule_ids_set |= set(rule_list)
    
    #print "Reachable Rules: %d" % len(rule_ids_set)
    start_packets = len(rule_lists)
    result_rule_lists = []
    while(len(rule_ids_set) > 0):
        max_score = 0
        max_score_index = 0
        for i in xrange(0, len(rule_lists)):
            rule_list = rule_lists[i]
            score = 0
            for r in rule_list:
                if r in rule_ids_set:
                    score += 1
            if score > max_score:
                max_score = score
                max_score_index = i
        
        max_score_rule_list = rule_lists[max_score_index]
        result_rule_lists.append(max_score_rule_list)
        
        # Rules that have been hit already
        rule_ids_set -= set(max_score_rule_list)
        del rule_lists[max_score_index]
    
    end_packets = len(result_rule_lists)
    print "Global Compression: Start=%d, End=%d, Ratio=%f" % (start_packets, end_packets, float(end_packets)/start_packets)
    return result_rule_lists

def find_test_packets(src_port_id):

    # Generate All-X packet
    all_x = byte_array_get_all_x(ntf_global.length)
    test_pkt = headerspace(ntf_global.length)
    test_pkt.add_hs(all_x)
       
    st = time.time()
    paths = find_reachability_test(ntf_global, ttf_global, src_port_id, dst_port_ids_global, test_pkt)
    en = time.time()
    
    print_paths_to_database(paths, port_reverse_map_global, TABLE_TEST_PACKETS)
    result_string = "Port:%d, Path No:%d, Time: %fs" % (src_port_id, len(paths), en - st)    
    print result_string

    # Compress
    st = time.time()
    paths = path_compress(paths)
    en = time.time()

    result_string = "Port:%d, Compressed Path No:%d, Time: %fs" % (src_port_id, len(paths), en - st)    
    print result_string
    
    print_paths_to_database(paths, port_reverse_map_global, TABLE_TEST_PACKETS_LOCALLY_COMPRESSED)

    return len(paths)

def chunks(l, n):
    """ Yield successive n chunks from l.
    """
    sub_list_length = len(l) / n
    
    for i in xrange(0, len(l), sub_list_length):
        if (i+sub_list_length >= len(l)):
            yield l[i:]
        else:
            yield l[i:i+sub_list_length]

def merge_chunks(chunks):
    result = []
    for chunk in chunks:
        result.extend(chunk)
    return result

def main():  
    global src_port_ids_global
    global dst_port_ids_global
    global port_map_global
    global port_reverse_map_global
    global ntf_global
    global ttf_global
     
    cs = cisco_router(1)
    output_port_addition = cs.PORT_TYPE_MULTIPLIER * cs.OUTPUT_PORT_TYPE_CONST
     
    # Load .tf files
    ntf_global = load_stanford_backbone_ntf()
    ttf_global = load_stanford_backbone_ttf()
    (port_map_global, port_reverse_map_global) = load_stanford_backbone_port_to_id_map()
    
    rule_count = 0
    for tf in ntf_global.tf_list:
        rule_count += len(tf.rules)    
    print "Total Rules: %d" % rule_count
    
    rule_count = len(ttf_global.rules) 
    print "Total Links: %d" % rule_count
   
    # Generate all ports
    for rtr in port_map_global.keys():
        src_port_ids_global |= set(port_map_global[rtr].values())
    
    for port in src_port_ids_global:
        port += output_port_addition
        dst_port_ids_global.add(port)
    
    #src_port_ids_global = set([1500002, 100003, 1600002])
    os.remove(DATABASE_FILE)
    
    # Initialize the database
    conn = sqlite3.connect(DATABASE_FILE)
    conn.execute('CREATE TABLE %s (header TEXT, input_port INTEGER, output_port INTEGER, ports TEXT, no_of_ports INTEGER, rules TEXT, no_of_rules INTEGER)' % TABLE_TEST_PACKETS)
    conn.execute('CREATE TABLE %s (header TEXT, input_port INTEGER, output_port INTEGER, ports TEXT, no_of_ports INTEGER, rules TEXT, no_of_rules INTEGER)' % TABLE_TEST_PACKETS_LOCALLY_COMPRESSED)
    conn.execute('CREATE TABLE %s (rules TEXT, no_of_rules INTEGER)' % TABLE_TEST_PACKETS_GLOBALLY_COMPRESSED)
    conn.commit()
    conn.close()
    
    # Run reachability
    start_time = time.time()
    
    pool = Pool(processes = CPU_COUNT - 1)
    result = pool.map_async(find_test_packets, src_port_ids_global)

    # Close
    pool.close()
    pool.join()
    
    end_time = time.time()
    
    test_packet_count = result.get()
    total_paths = sum(test_packet_count)    
    print "========== Before Compression ========="
    print "Total Paths = %d" % total_paths
    print "Average packets per port = %f" % (float(total_paths) / len(src_port_ids_global))
    print "Total Time = %fs" % (end_time - start_time)
    
    #Global Compressing 
    start_time = time.time()
       
    conn = sqlite3.connect(DATABASE_FILE, 6000)
    result_rule_lists = []
    query = "SELECT rules FROM %s"  % TABLE_TEST_PACKETS_LOCALLY_COMPRESSED
    rows = conn.execute(query)
    
    for row in rows:
        result_rule_lists.append(row[0].split())
  
    chunk_size = 40000
    while(True):
        pool = Pool(processes = CPU_COUNT - 1)
        
        no_of_chunks = len(result_rule_lists) / chunk_size + 1
        
        rule_list_chunks = chunks(result_rule_lists, no_of_chunks) 
           
        result = pool.map_async(rule_lists_compress, rule_list_chunks)

        # Close
        pool.close()
        pool.join()
        
        result_rule_lists = merge_chunks(result.get())
        
        if(no_of_chunks <= 1):
            break
    
    #result_rule_lists = rule_lists_compress(result_rule_lists)
    end_time = time.time()
    
    query = "INSERT INTO %s VALUES (?, ?)" % TABLE_TEST_PACKETS_GLOBALLY_COMPRESSED
    
    total_paths = len(result_rule_lists)
    total_length = 0
    
    for rule_list in result_rule_lists:
        total_length += len(rule_list)
        conn.execute(query, (" ".join(rule_list), len(rule_list)))
     
    conn.commit()    
    conn.close()
    
    print "========== After Compression ========="
    print "Total Paths = %d" % total_paths
    print "Average packets per port = %f" % (float(total_paths) / len(src_port_ids_global))
    print "Average length of rule list = %f" % (float(total_length) / total_paths)
    print "Total Time = %fs" % (end_time - start_time)
    
if __name__ == "__main__":
    main()
