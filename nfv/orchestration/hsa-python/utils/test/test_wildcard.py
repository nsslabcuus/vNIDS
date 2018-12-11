'''
Created on Jul 4, 2012

@author: peymankazemian
'''
import unittest
from utils.wildcard import *

class Test(unittest.TestCase):

    def testCreateAllSame(self):
        w = wildcard_create_bit_repeat(1,3)
        self.assert_(w.__str__(0) == "xxxxxxxx", "creating all-x failed")
        w = wildcard_create_bit_repeat(1,2)
        self.assert_(w.__str__(0) == "11111111", "creating all-1 failed")
        w = wildcard_create_bit_repeat(1,1)
        self.assert_(w.__str__(0) == "00000000", "creating all-0 failed")
        w = wildcard_create_bit_repeat(1,0)
        self.assert_(w.__str__(0) == "empty", "creating all-z failed")
      
    def testCreateFromInt(self):
        w = wildcard_create_from_int(0x7531,2)
        expected = wildcard_create_from_string("0111010100110001")
        self.assertTrue(wildcard_is_equal(w,expected))
      
    def testEqual(self):
        w1 = wildcard_create_from_string("101xx011")
        w2 = wildcard_create_from_string("xxxxx001")
        self.assertTrue(wildcard_is_equal(w1,w1))
        self.assertFalse(wildcard_is_equal(w1,w2))
          
    def testLogical(self):
        w1 = wildcard_create_from_string("101xx011")
        w2 = wildcard_create_from_string("1xxxx001")
        w_and = wildcard_and(w1,w2)
        w_and_result = wildcard_create_from_string("10xxx001")
        w_or = wildcard_or(w1,w2)
        w_or_result = wildcard_create_from_string("1x1xx011")
        w_not = wildcard_not(w1)
        w_not_result = wildcard_create_from_string("010xx100")
        self.assertTrue(wildcard_is_equal(w_and,w_and_result))
        self.assertTrue(wildcard_is_equal(w_or,w_or_result))
        self.assertTrue(wildcard_is_equal(w_not,w_not_result))
      
    def testIntersect(self):
        w1 = wildcard_create_from_string("1001xxxx")
        w2 = wildcard_create_from_string("1xxx1111")
        w = wildcard_intersect(w1,w2)
        self.assert_(w.__str__(0) == "10011111", "Incorrect Intersection")
        
        w1 = wildcard_create_from_string("101xxxx1")
        w2 = wildcard_create_from_string("xxxxx001")
        w = wildcard_intersect(w1,w2)
        self.assert_(w.__str__(0) == "101xx001", "Incorrect Intersection")
        
        w3 = wildcard_not(wildcard_create_from_string("01000000"))
        w = wildcard_intersect(w1,w3)
        self.assert_(w.__str__(0) == "10111111", "Incorrect Intersection with Not")
        
    def testEmptyIntersect(self):
        w1 = wildcard_create_bit_repeat(1,2)
        w0 = wildcard_create_bit_repeat(1,1)
        w = wildcard_intersect(w1,w0)
        self.assert_(w.__str__(0) == "empty", "Expected empty intersection, found non-empty")
        
    def testSetByteAndBit(self):
        w = wildcard_create_bit_repeat(5,2)
        w[3] = 0x55ff
        expected = wildcard_create_from_string("11111111,0000xxxx,11111111,11111111,11111111")
        self.assertTrue(wildcard_is_equal(w,expected))
        w[(3,7)] = 2
        expected = wildcard_create_from_string("11111111,1000xxxx,11111111,11111111,11111111")
        self.assertTrue(wildcard_is_equal(w,expected))
        
    def testRewrite(self):
        w = wildcard_create_from_string("1001xxxx")
        mask = wildcard_create_from_string("11000111")
        rewrite = wildcard_create_from_string("00101000")
        (r,card) = wildcard_rewrite(w,mask,rewrite)
        self.assertEqual(card,1)
        self.assert_(r.__str__(0) == "10101xxx")
       
    def testCompl(self):
      w = wildcard_create_from_string("1001xxxx")
      a = wildcard_complement(w)
      self.assertEqual(len(a), 4)
       
    def testEdgeCaseCompl(self):
      # all-x complement
      w = wildcard_create_bit_repeat(1,3)
      a = wildcard_complement(w)
      self.assertEqual(len(a), 0)
      # empty complement
      w = wildcard_create_bit_repeat(1,0)
      aa = wildcard_complement(w)
      self.assertEqual(len(aa), 1)
      self.assert_(aa[0].__str__(0) == "xxxxxxxx")
                   
    def testDiff(self):
      w = wildcard_create_from_string("1001xxxx")
      d = wildcard_create_from_string("100x00xx")
      l = wildcard_diff(w,d)
      self.assertEqual(len(l), 2)
      # w-w
      l = wildcard_diff(w,w)
      self.assertEqual(len(l), 0)
      # empty - non-empty
      e = wildcard_create_bit_repeat(1,0)
      l = wildcard_diff(e,d)
      self.assertEqual(len(l), 0)
      # w- empty
      l = wildcard_diff(w,e)
      self.assertEqual(len(l), 1)
      self.assert_(wildcard_is_equal(l[0],w))
  
        
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testCreateAllSame']
    unittest.main()