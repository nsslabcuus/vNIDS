'''
Created on Jun 26, 2012

Depreciated on July 10, 2012: this library should no longer be used. 
Replaced by wildcard.py.

@author: Peyman Kazemian
'''
from math import ceil

def byte_array_intersect(a1, a2):
    '''
    a1 n a2.
    '''
    if len(a1) != len(a2):
        return []
    result = bytearray()
    for i in range(len(a1)):
        b = a1[i] & a2[i]
        result.append(b)
        if (b & 0x03 == 0) or (b & 0x0c == 0) or (b & 0x30 == 0) or (b & 0xc0 == 0):
            return []
    return result


def byte_array_complement(a):
    '''
    a'
    '''
    result = []
    length = len(a)
    for i in range(length):
        for j in range(4):
            if (a[i] >> 2*j) & 0x03 == 0x01:
                all_x = byte_array_get_all_x(length)
                all_x[i] = ((0xFE << 2*j) & 0xff) | ((0xFF >> (8 - 2*j)) & 0xff)
                result.append(all_x)
            elif (a[i] >> 2*j) & 0x03 == 0x02:
                all_x = byte_array_get_all_x(length)
                all_x[i] = ((0xFD << 2*j) & 0xff) | ((0xFF >> (8 - 2*j)) & 0xff)
                result.append(all_x)
    return result

def byte_array_difference(a,b):
    ''''
    a - b = a n b'
    '''
    diff = []
    b_complement = byte_array_complement(b)
    for b_array in b_complement:
        isect = byte_array_intersect(a,b_array)
        if isect != []:
            diff.append(isect)
    return diff

def byte_array_equal(a1,a2):
    '''
    checks if a1=a2.
    '''
    r = a1.__eq__(a2)
    return r

def byte_array_list_contained_in(list_a,list_b):
    result = True
    for a in list_a:
        this_result = False
        for b in list_b:
            if byte_array_equal(a,b):
                this_result = True
                break
        if this_result == False:
            result = False
            break
    return result

def byte_array_subset(a, b):
    '''
    checks if a is subset of b.
    doesn't work if a is empty
    '''
    for i in range(len(a)):
        if (a[i] & ~b[i]):
            return False
    return True


def byte_array_and(b1, b2):
    '''
    perform 'and' operation when b1 and b2 can have wildcard bits
    '''
    b_out = bytearray()
    for i in range(len(b1)):
        tmp = (b1[i] & b2[i] & 0xaa) | ((b1[i] | b2[i]) & 0x55)
        b_out.append(tmp);
    return b_out

def byte_array_or(b1, b2):
    '''
    perform 'or' operation when b1 and b2 can have wildcard bits
    '''
    b_out = bytearray()
    for i in range(len(b1)):
        tmp = (b1[i] & b2[i] & 0x55) | ((b1[i] | b2[i]) & 0xaa)
        b_out.append(tmp);
    return b_out

def byte_array_not(b):
    '''
    perform 'or' operation when b1 and b2 can have wildcard bits
    '''
    b_out = bytearray()
    for i in range(len(b)):
        tmp = ((b[i] << 1) & 0xaa) | ((b[i] >> 1) & 0x55)
        b_out.append(tmp);
    return b_out

def byte_array_wildcard_to_mask_match_strings(byte_array):
    if byte_array == None:
        return "None"
    str_mask = ""
    str_match = ""
    for b in byte_array:
        for i in range(4):
            b_shift = b >> (i * 2)
            next_bit = b_shift & 0x03
            if (next_bit == 0x01):
                str_mask = "1" + str_mask
                str_match = "0" + str_match
            elif (next_bit == 0x02):
                str_mask = "1" + str_mask
                str_match = "1" + str_match
            elif (next_bit == 0x03):
                str_mask = "0" + str_mask
                str_match = "0" + str_match
            else:
                str_mask = "0" + str_mask
                str_match = "1" + str_match
    return [str_mask,str_match]

def byte_array_to_hs_string(byte_array):
    if byte_array == None:
        return "None"
    str = ""
    for b in byte_array:
        for i in range(4):
            b_shift = b >> (i * 2)
            next_bit = b_shift & 0x03
            if (next_bit == 0x01):
                str = "0" + str
            elif (next_bit == 0x02):
                str = "1" + str
            elif (next_bit == 0x03):
                str = "x" + str
            else:
                str = "z" + str
    return str

def byte_has_no_x(b):
    for i in range(4):
        b_shift = b >> (i * 2)
        next_bit = b_shift & 0x03
        if (next_bit == 0x03 or next_bit == 0):
            return False
    return True

def byte_to_int(b):
    val = 0
    for i in range(4):
        b_shift = b >> (i * 2)
        next_bit = b_shift & 0x03
        if (next_bit == 0x02):
            val = val + 2**i
        elif (next_bit != 0x01):
            return None
    return val

def byte_array_to_pretty_hs_string(byte_array):
    if byte_array == None:
        return "None"
    string = ""
    cntr = -1
    pretty_flag = False
    for b in byte_array:
        cntr += 1
        if (cntr % 2 == 0 and cntr+1 < len):
            if (byte_has_no_x(byte_array[cntr]) and byte_has_no_x(byte_array[cntr+1])):               
                pretty_flag = True
                val = byte_to_int(byte_array[cntr]) + byte_to_int(byte_array[cntr+1])*16
                if cntr > 0:
                    string = "D%d,%s"%(val,string)
                else:
                    string = "D%d%s"%(val,string)
                continue
        elif (pretty_flag):
            pretty_flag = False
            continue
        
        if (cntr % 2 == 0 and cntr > 0):
            string = "," + string
        for i in range(4):
            b_shift = b >> (i * 2)
            next_bit = b_shift & 0x03
            if (next_bit == 0x01):
                string = "0" + string
            elif (next_bit == 0x02):
                string = "1" + string
            elif (next_bit == 0x03):
                string = "x" + string
            else:
                string = "z" + string
        
    return string

def hs_string_to_byte_array(str):
    if str == None:
        return None
    if str == "None":
        return None
    strlen = len(str)
    ln = int(ceil(strlen / 4.0))
    br = bytearray()
    for j in range(ln):
        substr = str[max(0,strlen-4*j-4):strlen-4*j]
        next_byte = 0
        sublen = len(substr)
        for i in range(4):
            if i > sublen-1:
                next_byte = next_byte | (0x03 << 2*i)
            elif (substr[i] == 'X' or substr[i] == 'x'):
                next_byte = next_byte | (0x03 << 2*(sublen-i-1))
            elif (substr[i] == '1'):
                next_byte = next_byte | (0x02 << 2*(sublen-i-1))
            elif (substr[i] == '0'):
                next_byte = next_byte | (0x01 << 2*(sublen-i-1))
            elif (substr[i] == 'Z' or substr[i] == 'z'):
                next_byte = next_byte | (0x00 << 2*(sublen-i-1))   
        br.append(next_byte)
    return br

def int_to_byte_array(int_value, len):
    '''
    reads len bits from int_value and converts it to a bytearray of len ceil(len/4).
    Note: len should be a multiple of 4.
    '''
    ln = int(ceil(len/4.0))
    br = bytearray()
    for j in range(ln):
        nible = (int_value >> 4*j) & 0xf
        next_byte = 0
        for i in range(4):
            if (nible >> i) & 0x1 == 0:
                next_byte = next_byte | (0x01 << 2*i)
            if (nible >> i) & 0x1 == 1:
                next_byte = next_byte | (0x02 << 2*i)
        br.append(next_byte)
    return br

def byte_array_get_all_x(length):
    b = bytearray()
    for i in range(length):
        b.append(0xFF)
    return b
        
def byte_array_get_all_one(length):
    b = bytearray()
    for i in range(length):
        b.append(0xaa)
    return b
        
def byte_array_get_all_zero(length):
    b = bytearray()
    for i in range(length):
        b.append(0x55)
    return b
        
def byte_array_set_bit(b_array,byte,bit,value):
    if byte>=len(b_array) | bit >= 4:
        return False
    else:
        b_array[byte] = (b_array[byte] & ~(0x3 << bit*2) | (value << bit*2))
        return True
        
def byte_array_get_bit(b_array,byte,bit):
    if byte>=len(b_array) | bit >= 4:
        return 0x04;
    else:
        return (b_array[byte] >> 2*bit) & 0x03;
        
def byte_array_set_bytes(b_array, byte, value, num_bytes):
    if byte+num_bytes>len(b_array):
        return False
    else:
        for i in range(num_bytes):
            b_array[byte+i] = (value >> i*8) & 0xff
        return True
    
def byte_array_compress_list(ba_list):
    pop_index = []
    for i in range(len(ba_list)):
        for j in range(i+1,len(ba_list)):
            if byte_array_subset(ba_list[i],ba_list[j]):
                pop_index.append(i)
            elif byte_array_subset(ba_list[j],ba_list[i]):
                pop_index.append(j)
    result = []
    for k in range(len(ba_list)):
        if k not in pop_index:
            result.append(ba_list[k])
    return result
        
def byte_array_rewrite(b_array,mask,rewrite):
    b_out = bytearray()
    count = 0
    for i in range(len(b_array)):
        tmp = (((b_array[i] | mask[i]) & rewrite[i]) & 0x55) | \
              (((b_array[i] & mask[i]) | rewrite[i]) & 0xaa)
        b_out.append(tmp);
        wc_counter = mask[i] & b_array[i] & b_array[i] >> 1
        if wc_counter & 0x01 != 0: 
            count += 1
        if wc_counter & 0x04 != 0: 
            count += 1 
        if wc_counter & 0x10 != 0: 
            count += 1
        if wc_counter & 0x40 != 0: 
            count += 1
    return (b_out,count)

    
