'''
Created on Jul 2, 2012

@author: peymank
'''
import unittest
from utils.wildcard import wildcard_create_from_string
from headerspace.hs import headerspace

class Test(unittest.TestCase):

    def testCreate(self):
        '''
        Test if creating a headerspace object creates correct number of 
        bytearrays inside.
        '''
        h = headerspace(1)
        h.add_hs(wildcard_create_from_string("1001xxxx"))
        h.add_hs(wildcard_create_from_string("11xxxx11"))
        self.assertEqual(h.count(),2)
    
    def testDiffHS(self):
        '''
        Test the diff (lazy subtraction):
        1) adding a diff before having anything doesn't add any diff to hs
        2) adding a diff actually adds correct number of diff bytearrays
        3) adding a new bytearray that has intersection with a previously added
        diff doesn't add that diff to the new bytearray.
        '''
        h = headerspace(1)
        h.diff_hs(wildcard_create_from_string("1001xxxx"))
        h.add_hs(wildcard_create_from_string("1001xxxx"))
        h.add_hs(wildcard_create_from_string("11xxxx11"))
        self.assertEqual(h.count_diff(),0)
        h.diff_hs(wildcard_create_from_string("1xxx1111"))
        self.assertEqual(h.count_diff(),2)
        h.add_hs(wildcard_create_from_string("xxxxxx11"))
        self.assertEqual(h.count_diff(),2)
        
    def testCopy(self):
        '''
        Test if copy works correctly
        Adding new stuff on the original hs, doesn't affect copied hs.
        '''
        h = headerspace(1)
        h.add_hs(wildcard_create_from_string("1001xxxx"))
        h.add_hs(wildcard_create_from_string("11xxxx11"))
        h.diff_hs(wildcard_create_from_string("100x0000"))
        h.diff_hs(wildcard_create_from_string("1xxx1111"))
        hcpy = h.copy()
        self.assertEqual(h.count(),hcpy.count())
        self.assertEqual(h.count_diff(),hcpy.count_diff())
        h.add_hs(wildcard_create_from_string("100100xx"))
        self.assertEqual(h.count(),3)
        self.assertEqual(h.count_diff(),3)
        self.assertEqual(hcpy.count(),2)
        self.assertEqual(h.count_diff(),3)        
                
    def testIntersect1(self):
        '''
        Test intersect with a bytearray
        '''
        h = headerspace(1)
        h.add_hs(wildcard_create_from_string("1001xxxx"))
        h.add_hs(wildcard_create_from_string("11xxxx11"))
        h.diff_hs(wildcard_create_from_string("100xx000"))
        h.diff_hs(wildcard_create_from_string("1xxx1x11"))
        h.intersect(wildcard_create_from_string("xxxxx011"))
        self.assertEqual(h.count(),2)
        self.assertEqual(h.count_diff(),2)
    
    def testIntersect2(self):
        '''
        Test intersect with a headerspace
        '''
        h = headerspace(1)
        h.add_hs(wildcard_create_from_string("1001xxxx"))
        h.add_hs(wildcard_create_from_string("11xxxx11"))
        h.diff_hs(wildcard_create_from_string("100xx000"))
        h.diff_hs(wildcard_create_from_string("1xxx1x11"))
        other = headerspace(1)
        other.add_hs(wildcard_create_from_string("10xxxxx1"))
        other.diff_hs(wildcard_create_from_string("10010xxx"))
        h.intersect(other)
        self.assertEqual(other.count(),1)
        self.assertEqual(other.count_diff(),1)
        self.assertEqual(h.count(),1)
        self.assertEqual(h.count_diff(),2)
        
    def testComplement(self):
        '''
        Test if complement correctly handles diffs
        '''
        h = headerspace(1)
        h.add_hs(wildcard_create_from_string("1001xxxx"))
        h.diff_hs(wildcard_create_from_string("100xx000"))
        h.complement()
        self.assertEqual(h.count(),5)
        
    def testMinus(self):
        h1 = headerspace(1)
        h1.add_hs(wildcard_create_from_string("1001xxxx"))
        h2 = headerspace(1)
        h2.add_hs(wildcard_create_from_string("100xx000"))
        h1.minus(h2)
        self.assertEqual(h1.count(),3)
        
    def testSelfDiff(self):
        h = headerspace(1)
        h.add_hs(wildcard_create_from_string("1001xxxx"))
        h.add_hs(wildcard_create_from_string("11xxxx11"))
        h.diff_hs(wildcard_create_from_string("100xxx00"))
        h.diff_hs(wildcard_create_from_string("1xxxx111"))
        h.self_diff()
        self.assertEqual(h.count(),5)
        self.assertEqual(h.count_diff(),0)
        
    def testContainedIn(self):
        h1 = headerspace(1)
        h1.add_hs(wildcard_create_from_string("1001xxxx"))
        h1.diff_hs(wildcard_create_from_string("1xxxx111"))
        h2 = headerspace(1)
        h2.add_hs(wildcard_create_from_string("1001xxxx"))
        h2.add_hs(wildcard_create_from_string("11xxxx11"))
        h2.diff_hs(wildcard_create_from_string("100xxx00"))
        h2.diff_hs(wildcard_create_from_string("1xxxx111"))
        self.assertTrue(h1.is_contained_in(h2))
        self.assertFalse(h2.is_contained_in(h1))
              
if __name__ == "__main__":
    
    import sys
    sys.argv = ['', 'Test.testCreate','Test.testDiffHS','Test.testCopy',\
                'Test.testIntersect1','Test.testIntersect2',\
                'Test.testComplement','Test.testMinus','Test.testSelfDiff'] 
    unittest.main()