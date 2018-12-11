#!/usr/bin/env python
# coding=utf-8

import httplib
import json
import subprocess 


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
        subprocess.call(["curl", "http://10.10.1.4:8080/wm/staticflowpusher/clear/00:00:74:a0:2f:5f:17:e4/json"]) 
    
    def list(self, data):
        ret = self.rest_call(data, 'LIST')
        return ret[0] == 200

    def rest_call(self, data, action):
        if action is 'LIST' :
            path = '/wm/staticflowpusher/list/00:00:74:a0:2f:5f:17:e4/json'
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
        print ret
        conn.close()
        return ret

pusher = StaticFlowPusher('10.10.1.4')

command="ovs-ofctl show ovs-lan|grep `xl list|grep 'firewall_01'|awk '{print $2}'`'.0'|cut -d '(' -f1";
trafficPort=subprocess.check_output(command, shell=True);
command="ovs-ofctl show ovs-lan|grep `xl list|grep 'firewall_01'|awk '{print $2}'`'.2'|cut -d '(' -f1";
messagePort=subprocess.check_output(command, shell=True);

trafficPort=trafficPort.strip().rstrip()
messagePort=messagePort.strip().rstrip()

# from client to clickos 
flow1 = {
    "switch": "00:00:74:a0:2f:5f:17:e4", 
    "name":"client-server", 
    "cookie":"1", 
    "eth_vlan_vid":"0x000",
    # from client to clickos 
    "eth_src":"a0:ec:f9:e8:ac:69", "eth_dst":"00:00:00:00:01:00", 
    "active":"true",
    # Send to clickos eth0
    "actions":"pop_vlan,output="+trafficPort
}

# from server to clickos 
flow2 = {
    "switch": "00:00:74:a0:2f:5f:17:e4", 
    "name":"server-client", 
    "cookie":"2", 
    "eth_vlan_vid":"0x000",
    # from server to clickos  
    "eth_src":"a0:ec:f9:e8:a4:72", "eth_dst":"00:00:00:00:01:00", 
    "active":"true",
    # Send to clickos eth0
    "actions":"pop_vlan,output="+trafficPort
}

# from localhost to clickos.
flow3 = {
    "switch": "00:00:74:a0:2f:5f:17:e4", 
    "name":"locl-clickos", 
    "cookie":"17", 
    # from localhost to clickos 
    "eth_src":"74:a0:2f:5f:17:e4", "eth_dst":"00:00:00:00:01:02", 
    "active":"true",
    # Send to clickos eth2
    "actions":"output="+messagePort
}

# from clickos to server. 
flow4 = {
    "switch": "00:00:74:a0:2f:5f:17:e4", 
    "name":"clickos-server", 
    "cookie":"4", 
    # from clickos to server 
    "eth_src":"00:00:00:00:01:00", "eth_dst":"a0:ec:f9:e8:a4:72", 
    "active":"true",
    "actions":"output=2"
}

# from clickos to client. 
flow5 = {
    "switch": "00:00:74:a0:2f:5f:17:e4", 
    "name":"clickos-client", 
    "cookie":"5", 
    # from clickos to client 
    "eth_src":"00:00:00:00:01:00", "eth_dst":"a0:ec:f9:e8:ac:69", 
    "active":"true",
    "actions":"output=1"
}

pusher.set(flow1)
pusher.set(flow2)
pusher.set(flow3)
pusher.set(flow4)
pusher.set(flow5)



