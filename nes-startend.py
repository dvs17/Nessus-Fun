#!/usr/bin/python
'''
Nessus Results Extractor for Cyber Essetials Test
created by dvs

Usage:
python cyber-e.py [Directory Nessus files are stored]
'''
import xml.etree.ElementTree as ET
global str
import os
import sys
import re
from decimal import Decimal
ip = " "
v = " "
def select_files_in_folder(dir, ext):
    for file in os.listdir(dir):
        if file.endswith('.%s' % ext):
            yield os.path.join(dir, file)

for file in select_files_in_folder(sys.argv[1], 'nessus'):
	tree = ET.parse(file)
	root = tree.getroot()

	for a in root.findall('Report/ReportHost'):
		ipaddr = a.attrib[ 'name' ]
		start_time = ""
		end_time = ""
		hostne = ""
		for b in a.getchildren():
			for c in b.getchildren():
				if c.get('name') == "netbios-name":
					hostne = c.text
				elif c.get('name') == "hostname":
					hostne = c.text
				elif c.get('name') == "host-fqdn":
					hostne = c.text.split(".")[0]

				if b.tag == "HostProperties":
					if c.get("name") == "HOST_END":
						end_time = c.text
					if c.get("name") == "HOST_START":
						start_time = c.text
		print ipaddr + "("+ hostne + ")" +"\t""\t"+ "START: " + start_time + "\t""\t" +"END: "+ end_time

