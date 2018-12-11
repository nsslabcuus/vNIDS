#!/usr/bin/env python
# coding=utf-8

import httplib
import json
import subprocess
from floodlight_config_parser import FlowEntryParser
import argparse


class StaticFlowPusher(object):

    def __init__(self, server):
        self.server = server

    def get(self, data):
        ret = self.rest_call({}, 'GET')
        return json.loads(ret[2])

    def set(self, data):
        ret = self.rest_call(data, 'POST')
        return ret[0] == 200

    def remove(self, objtype, data):
        ret = self.rest_call(data, 'DELETE')
        return ret[0] == 200
    
    def clear(self):
        subprocess.call(["curl", "http://10.130.127.3:8080/wm/staticflowpusher/clear/00:00:00:00:00:00:00:01/json"]) 
    
    def list(self, data):
        ret = self.rest_call(data, 'LIST')
        return ret[0] == 200

    def rest_call(self, data, action):
        if action is 'CLEAR' :
            path = '/wm/staticflowpusher/clear/00:00:00:00:00:00:00:01/json'
        elif action is 'LIST' :
            path = '/wm/staticflowpusher/list/00:00:00:00:00:00:00:01/json'
        else: 
            path = '/wm/staticflowpusher/json'
        
        headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json',
        }
        body = json.dumps(data)
        conn = httplib.HTTPConnection(self.server, 8080)
        conn.request(action, path, body, headers)
        response = conn.getresponse()
        ret = (response.status, response.reason, response.read())
        # print ret
        conn.close()
        return ret


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=str, help="config file name")
    parser.add_argument("interface", type=str, help="interface ip address")
    args = parser.parse_args()

    pusher = StaticFlowPusher(args.interface)

    FCP = FlowEntryParser(args.file)
    FCP.decode_config()
    if FCP.check_config() is True:
        count = 0
        for flow_entry_name, flow_entry_conf in FCP.config.items():
            pusher.set(flow_entry_conf)
            count += 1
        print "%d rules have been sent" % count
