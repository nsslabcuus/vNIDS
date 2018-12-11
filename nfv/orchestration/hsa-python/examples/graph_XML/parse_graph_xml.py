'''
Created on Jul 27, 2012

@author: peymankazemian
'''
from config_parser.graph_xml_parser import graph_xml

g = graph_xml()
g.set_device_types(["Router"])
g.read_graphs_xml("graphs.xml")
g.read_links_xml("links.xml")
g.read_nodes_xml("nodes.xml")
print g.generate_topology_list()
print g.generate_node_names()
