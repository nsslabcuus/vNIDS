#!/usr/bin/env python
# coding=utf-8
'''
    Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
    a special exception, as described in included LICENSE_EXCEPTION.txt.
    
Created on Jun 7, 2012

@author: Peyman Kazemian
'''

import headerspace.hs as hs
import utils.wildcard as uw


# Creating a header space object of length 8 bits (1 byte)
hsl = hs.headerspace(4)

# Adding some wildcard expressions to the headerspace object
hsl.add_hs(uw.wildcard_create_from_string("00001010100000100111111100000011"))
hsl.add_hs(uw.wildcard_create_from_int(175668993, 4)) # 10.120.127.1
hsl.add_hs(uw.wildcard_create_from_string("000010101000001001111111xxxxxxxx"))
print "original HS is\n",hsl,"\n---------"

# Removing some wildcard expressions from the headerspace object
#hsl.diff_hs(uw.wildcard_create_from_string("1010011x"))
#hsl.diff_hs(uw.wildcard_create_from_string("1010xxx0"))
#print "New HS is\n",hsl,"\n---------"

# Intersecting this headerspace with some wildcard expression
hsl.intersect(uw.wildcard_create_from_string("00001010100000101000000000000001"))
print "After intersection HS is\n",hsl,"\n---------"

# Forcing the subtraction to be computed
#hsl.self_diff()
#print "Calculating the difference:\n",hsl,"\n---------"

