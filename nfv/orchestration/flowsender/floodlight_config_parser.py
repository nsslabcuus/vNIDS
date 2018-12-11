import json
import os
import re


class FlowEntryParser:
    def __init__(self, filename):
        self.config_filename = filename
        self.config = {}

        # In here we define some fields that must or optional contained by
        # an entry in the config file.
        self.must_field = ("name", "switch")
        self.optional_field = ("name","switch", "priority", "cookie", "active", "ipv4_src", "ipv4_dst", "in_port", "eth_dst", "eth_src", "input", "eth_type", "eth_vlan_vid", "instruction_apply_actions","actions","ip_proto" )
        self.action_field = ("pop_vlan", "push_vlan", "output", "set_eth_dst", "set_eth_src", "flood","set_field")

    def decode_config(self):
        with open(os.path.join(os.getcwd(), self.config_filename), 'r') as config_file:
            val = config_file.read()
            self.config = json.loads(val)

    def check_config(self):
        print "-------------- Check Config Entry...... ----------------------------"
        for flow_entry_name, flow_entry_conf in self.config.items():
            # check must field
            for field in self.must_field:
                if field not in flow_entry_conf:
                    print flow_entry_name + " is not illegal entry! Because the missing field of " + field
                    return False
            
            # check undefined field
            for field_name, field_value in flow_entry_conf.items():
                if field_name not in self.must_field and field_name not in self.optional_field:
                    print flow_entry_name + " is not illegal entry! Because the " + field + " field is undefined"
                    return False

            # check the whether all the action filed is defined
            actions = flow_entry_conf["instruction_apply_actions"].split(',')
            for action in actions:
                action_key = re.split('=|->', action)[0].strip()
                if action_key not in self.action_field:
                    print flow_entry_name + " is not illegal entry! Because the " + action_key + " is not illegal action field"
                    return False
        print "-------------- Check Finished --------------------------------------"
        return True

if __name__ == '__main__':
    FCP = FlowEntryParser()
    FCP.decode_config()
    FCP.check_config()

