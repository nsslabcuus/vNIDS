'''
    Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
    a special exception, as described in included LICENSE_EXCEPTION.txt.
    
Created on Jun 7, 2012

@author: Peyman Kazemian
'''
from headerspace.hs import *
from headerspace.tf import *

# Create a transfer function object for packet header of length 1 byte
tf = TF(1)
    
# Adding rules to the transfer function
tf.add_rewrite_rule(TF.create_standard_rule([1,2,3], "100100xx", [5], "00111111", "01100000","",[]))
tf.add_rewrite_rule(TF.create_standard_rule([1,2], "1001xxxx", [5], "00001111", "01100000","",[]))
tf.add_fwd_rule(TF.create_standard_rule([1,2], "000011xx", [5], None, None,"",[]))
tf.add_fwd_rule(TF.create_standard_rule([2,4], "10xxxxxx", [5], None , None,"",[]))

print tf
 
# Apply a headerspace object to TF we expect this to match on rule 1,2,4
hs = headerspace(1)
hs.add_hs(wildcard_create_from_string("100xxxxx"))
result = tf.T(hs,2)
print "Result is:\n---------"
for (h,p) in result:
        print "at port %s:\n%s"%(p,h)
        print "#"
        
# Computing Inverse Transfer function
print "\n--------\nINVERSE\n--------\n"
result = tf.T_inv(hs, 5)
print "Result is:\n---------"
for (h,p) in result:
    print "at port %s:\n%s"%(p,h)
    print "#"