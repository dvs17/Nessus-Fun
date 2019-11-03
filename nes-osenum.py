#!/usr/bin/python3.6
'''
Nessus Vulnerability name and plugnID Extractor
created by dvs

Usage:
python vuln-id.py [Directory Nessus files are stored]
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
		for b in a.getchildren():
			for c in b.getchildren():
				if c.get('name') == "netbios-name":
					hostname = c.text
				elif c.get('name') == "hostname":
					hostname = c.text
				elif c.get('name') == "host-fqdn":
					hostname = c.text

			if b.tag == "ReportItem":
				if "11936" in b.attrib[ 'pluginID' ]:
					if "Method : SMB_OS" in b.findtext('plugin_output'):
						ipaddr = a.attrib[ 'name' ]
						osenum = b.findtext('plugin_output')
						print ipaddr+"\t"+"("+hostname+")\t"+osenum.strip().split(": ")[1].replace("Confidence level", "")
					elif "Method : MSRPC" in b.findtext('plugin_output') and "Confidence level : 99" in b.findtext('plugin_output'):
						ipaddr = a.attrib[ 'name' ]
						osenum = b.findtext('plugin_output')
						print ipaddr+"\t"+"("+hostname+")\t"+osenum.strip().split(": ")[1].replace("Confidence level", "") 
