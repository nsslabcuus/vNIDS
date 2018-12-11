'''
Created on Jul 10, 2012

@author: Peyman Kazemian
'''
from utils.hs_hash_table import hs_hash_table
from utils.wildcard import wildcard_create_bit_repeat

class exact_match_hash_table(hs_hash_table):
    '''
    A hash table that only looks at exact match bits.
    '''


    def __init__(self,match_indices):
        '''
        Constructor
        '''
        self.match_indices = match_indices
        self.inport_to_table = {}
        
    def add_entry(self,wildcard_match,ports,obj):
        m = wildcard_create_bit_repeat(len(self.match_indices),1)
        for i in range(len(self.match_indices)):
            m[i] = wildcard_match[self.match_indices[i]]
        match_key_string = "%s"%m
        if 'x' in match_key_string:
            match_key_string = "default"
        for port in ports:
            if str(port) not in self.inport_to_table.keys():
                self.inport_to_table[str(port)] = {}
            if match_key_string not in self.inport_to_table[str(port)].keys():
                self.inport_to_table[str(port)][match_key_string] = []
            self.inport_to_table[str(port)][match_key_string].append(obj)
        
    
    def del_entry(self,wildcard_match,ports,obj):
        pass
    
    def find_entries(self,wildcard_search,port):
        m = wildcard_create_bit_repeat(len(self.match_indices),1)
        for i in range(len(self.match_indices)):
            m[i] = wildcard_search[self.match_indices[i]]
        match_key_string = "%s"%m
        index = match_key_string.find('x')
        if index != -1:
            match_key_string = match_key_string[:index]
        elif index == 0:
            return None
        rule_set = []
        try:
            if len(match_key_string) == len(self.exact_match_indices) * 8:
                #full match
                rule_set = self.inport_to_table["%d"%port][match_key_string] \
                    + self.inport_to_table["%d"%port]["default"]
            else:
                #partial match
                for key in self.exact_match_hash["%d"%port].keys():
                    if key.startswith(match_key_string):
                        rule_set += self.inport_to_table["%d"%port][key]
                rule_set += self.inport_to_table["%d"%port]["default"]
        except:
            rule_set = self.exact_match_hash["%d"%port]["default"]
        
        return rule_set
            
            