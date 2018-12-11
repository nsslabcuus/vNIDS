'''
Created on Aug 1, 2012

@author: Peyman Kazemian
'''

from examples.utils.cisco_tf_generator import generate_transfer_functions
from config_parser.graph_xml_parser import graph_xml

g = graph_xml()
g.set_device_types(["Router"])
g.read_graphs_xml("path_to_graphs.xml")
g.read_links_xml("path_to_links.xml")
g.read_nodes_xml("path_to_nodes.xml")

settings = {"rtr_names": g.generate_node_names(),
            "input_path": "input_files",
            "output_path":"tf_files",
            "topology":g.generate_topology_list()
            }


generate_transfer_functions(settings)