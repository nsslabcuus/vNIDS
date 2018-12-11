#!/usr/bin/env python
# coding=utf-8

import subprocess
import json
import sys

ret=subprocess.check_output(["curl", "http://10.10.1.4:8080/wm/core/switch/00:00:74:a0:2f:5f:17:e4/port/json"]);





def json_parse_string(jobj, path):
        sys.stdout.write(path+"/")
        print jobj

def json_parse_number(jobj, path):
    sys.stdout.write(path+"/")
    print jobj

def json_parse_real(jobj, path):
    sys.stdout.write(path+"/")
    print jobj

def json_parse_bool(jobj, path):
    sys.stdout.write(path+"/")
    print jobj


def json_parse_object(jobj, path):
    for key in jobj:
        #old_path = path
        #json_parse(jobj[key], old_path+"/"+key)
        json_parse(jobj[key], path+"/"+key)

def json_parse_array(jobj, path):
    index = 0
    for element in jobj:
        #        old_path = path
        #json_parse(element, old_path+"/"+"["+str(index)+"]")
        json_parse(element, path+"/"+"["+str(index)+"]")
        index += 1



def json_parse(jobj, path):
    data_type = type(jobj)
    if data_type is unicode:
    #        print "string"
        json_parse_string(jobj, path)
        return 1
    elif data_type is int or data_type is long:
        #        print "number"
        json_parse_number(jobj, path)
        return 2
    elif data_type is float :
        #        print "real"
        json_parse_real(jobj, path)
        return 3
    elif data_type is bool :
        #        print "boolean"
        json_parse_bool(jobj, path)
        return 4
    elif data_type is dict :
        #        print "object"
        json_parse_object(jobj, path)
        return 5
    elif data_type is list :
        #        print "array"
        json_parse_array(jobj, path)
        return 6
    elif data_type is None :
        #        print "null"
        return 7
    else:
        #        print "Unknow Type!"
        return 0 


js_value=json.loads(ret);
jj=json_parse(js_value,"");



