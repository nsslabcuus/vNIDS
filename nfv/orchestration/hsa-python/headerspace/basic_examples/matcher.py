#!/usr/bin/env python
# coding=utf-8

import headerspace.hs as hs
import utils.wildcard as uw
from copy import deepcopy
import socket, struct  

class space(object):
    '''
    A class representing flow and firewall rules.
    '''
    
    def __init__(self):
        self.src = hs.headerspace(4)
        self.dst = hs.headerspace(4)

    @property
    def __deepcopy__(self, memo):
        newone = type(self)()
        newone.src = deepcopy(self.src, memo)
        newone.dst = deepcopy(self.dst, memo) 

    def ip2long(self, ipStr):
        '''
        Convert and IP string to long
        @ipstr: an IP string. E.g., 10.130.127.1
        '''
        packedIP = socket.inet_aton(ipStr)
        return long(struct.unpack("!L", packedIP)[0])

    def ip2wildcard(self, ipStr):
        '''
        Convert and IP string to wildcard format. 
        @ipstr: an IP string with mask. E.g., 10.130.127.1/24
        '''
        ret = ''
        srcIp = ipStr.split('/')
        for w in srcIp[0].split('.'):
            ret += format(int(w), '08b')
        len = int(srcIp[1])
        rev = 32 - len
        ret = ret[:len]
        i = 0
        while i < rev :
            ret += 'x'
            i += 1
        return ret

    def add_entry(self, srcStr, dstStr):
        '''
        Add a new entry (with src and dst IP addesses). 
        @srcStr: source IP string. E.g., 10.130.127.1 or 10.130.127.1/24
        @dstStr: destination IP string. E.g., 10.130.127.2 or 10.130.127.2/22
        '''
        if "/" not in srcStr :
            self.src.add_hs(uw.wildcard_create_from_int(self.ip2long(srcStr), 4))
        else:
            self.src.add_hs(uw.wildcard_create_from_string(self.ip2wildcard(srcStr)))
        if "/" not in dstStr :
            self.dst.add_hs(uw.wildcard_create_from_int(self.ip2long(dstStr), 4))
        else:
            self.dst.add_hs(uw.wildcard_create_from_string(self.ip2wildcard(dstStr)))

    def add_entry_str(self, srcStr, dstStr) :
        '''
        Add a new entry (with src and dst IP addesses). 
        @srcStr: source IP string. E.g., `00001010100001001111111100000010` 
        @dstStr: destination IP string. E.g., `000010101000010011111111000xxxxx`
        '''
        self.src.add_hs(srcStr)
        self.dst.add_hs(dstStr)
    
    def add_entry_list(self, srcs, dsts):
        '''
        Add entries by giving source IP address headerspace and destination IP 
        headerspace. 
        @srcs: source IP headerspace. 
        @dsts: destination IP headerspace. 
        '''
        self.src.add_hs_list(srcs)
        self.dst.add_hs_list(dsts)

    def intersect(self, other_sp):
        '''
        Intersect itself with other_sp. 
        The result will be saved in the caller instance itself. 
        We define two spaces intersect only when 1) they have their src and dst 
        intersect, and 2) they are not equal. 
        @other_sp: @type space: the other space to intersect with.
        '''
        if other_sp.__class__ == space:
            self.src.intersect(other_sp.src) 
            self.dst.intersect(other_sp.dst) 

    def is_intersect(self, other_sp):
        self.intersect(other_sp)
        if self.src.is_empty() or self.dst.is_empty() :
            return False
        else:
            return True

    def print_self(self):
        print "SrcIP:\n", self.src, "\n>>>>><<<<<\ndstIP:\n", self.dst 


index = 0
while index < 10000:
    index += 1
    sp1 = space()
    sp1.add_entry("10.130.127.1", "10.130.127.2")
    sp1.add_entry("10.130.127.1", "10.130.127.2/24")
    #print "ORIGINAL SPACE:"
    sp1.print_self()
    #print "======================================="
    sp2 = space()
    sp2.add_entry("10.130.127.1", "10.130.127.0/24")
    #sp1.intersect(sp2)
    #sp1.print_self()
    #print "======================================="

    if sp1.is_intersect(sp2):
        print "Intersection"
    else:
        print "No-intersection"

