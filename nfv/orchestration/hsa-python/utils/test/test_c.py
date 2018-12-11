'''
Created on Jul 3, 2012

@author: Peyman Kazemian
'''
from utils.wildcard import *
import copy

print "testing wildcard"
w1 = wildcard_create_bit_repeat(1, 2)
print w1
w2 = wildcard_create_from_string("10xxx001")
print w2
w3 = wildcard_create_from_string("11110000")
print w3
w4 = wildcard_create_from_string("101xxxxx")
print w4

wc = copy.deepcopy([w1])
print "deep copy",wc[0]
    
print "and ", wildcard_and(w2, w3)
print "or ", wildcard_or(w2, w3)
print "not ", wildcard_not(w3).__str__(0)
print "not not " , wildcard_not(wildcard_not(w3)).__str__(0)

print "isect " , wildcard_intersect(w2, w4)
print "complement "
for elem in wildcard_complement(w2):
    print "\t", elem
        
print "diff "
for elem in wildcard_diff(w2, w4):
    print "\t", elem

w4[0] = 0xff55
print "after rewriting first byte",w4
w4[(0,2)] = 3
print "after rewriting third bit",w4
