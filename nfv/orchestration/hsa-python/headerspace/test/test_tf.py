'''
Created on Jul 2, 2012

@author: Peyman Kazemian
'''
import unittest
from headerspace.tf import TF
from headerspace.hs import headerspace
from utils.wildcard import wildcard_create_from_string,wildcard_is_equal

class Test(unittest.TestCase):

    def testFwd(self):
        tf = TF(1)
        tf.add_fwd_rule(TF.create_standard_rule([1], "10xxxxxx", [2], \
                                                None, None))
        hs = headerspace(1)
        hs.add_hs(wildcard_create_from_string("1001xxxx"))
        result = tf.T(hs, 1)
        self.assertEqual(len(result), 1)
        self.assert_(wildcard_is_equal(result[0][0].hs_list[0],\
                                       wildcard_create_from_string("1001xxxx")))
        
    def testRW1(self):
        tf = TF(1)
        tf.add_rewrite_rule(TF.create_standard_rule([1], "10xxxxxx", [2], \
                                                "10011111", "01100000"))
        hs = headerspace(1)
        hs.add_hs(wildcard_create_from_string("1001xxxx"))
        result = tf.T(hs, 1)
        self.assertEqual(len(result), 1) 
        self.assert_(wildcard_is_equal(result[0][0].hs_list[0],\
                                       wildcard_create_from_string("1111xxxx")))
              
        
    def testRW2(self):
        tf = TF(1)
        tf.add_rewrite_rule(TF.create_standard_rule([1], "10xxxxxx", [2], \
                                                "10011111", "01100000"))
        hs = headerspace(1)
        hs.add_hs(wildcard_create_from_string("10xxxxxx"))
        hs.diff_hs(wildcard_create_from_string("101xxxxx"))
        result = tf.T(hs, 1)
        self.assertEqual(len(result), 1)
        self.assert_(wildcard_is_equal(result[0][0].hs_list[0],\
                                       wildcard_create_from_string("111xxxxx")))
        self.assertEqual(result[0][0].count_diff(),0)

    def testDependency(self):
        tf = TF(1)
        tf.add_fwd_rule(TF.create_standard_rule([1], "10xxxxxx", [2], \
                                                None, None))
        tf.add_rewrite_rule(TF.create_standard_rule([1], "1xxxxxxx", [3], "00111111", "10000000","",[]))
        hs = headerspace(1)
        hs.add_hs(wildcard_create_from_string("xxxxxxxx"))
        result = tf.T(hs, 1)
        self.assertEqual(len(result), 2, "Expecting both rules to be matched")
        self.assertTrue(wildcard_is_equal(
                                         result[1][0].hs_list[0],\
                                         wildcard_create_from_string("10xxxxxx"),\
                                         ), \
                        "unexpected second byte array")

    def testInverse(self):
        tf = TF(1)
        tf.add_rewrite_rule(TF.create_standard_rule([1], "10xxxxxx", [2], \
                                                "10011111", "01100000"))
        hs = headerspace(1)
        hs.add_hs(wildcard_create_from_string("111xxxxx"))
        hs.diff_hs(wildcard_create_from_string("1110xxxx"))
        result = tf.T_inv(hs, 2)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0].count(),1)
        self.assertEqual(result[0][0].count_diff(),1)
        self.assert_(wildcard_is_equal(result[0][0].hs_list[0],\
                                       wildcard_create_from_string("10xxxxxx"),\
                                       ))
        self.assert_(wildcard_is_equal(result[0][0].hs_diff[0][0],\
                                       wildcard_create_from_string("10x0xxxx"),\
                                       ))

if __name__ == "__main__":
    import sys;
    sys.argv = ['', 'Test.testDependency']
    unittest.main()