#!/bin/bash

python pymainsender.py file migrate_dst.cfg 1
python pymainsender.py file migrate_icmp.cfg 1 
python pymainsender.py file migrate_end.cfg 1

