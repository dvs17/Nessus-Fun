#!/usr/bin/python3.5m
'''
Nessus Results Extractor KB Patches
created by dvs and dbi

Usage:
python3.5m kbxtract.py [Nessus files] | sed '/^$/d'

History
-------
10/10/2016 -- Count total number of Patches Missing by DBI
11/10/2016 -- Edited Count Patches by DVS
12/10/2016 -- Remove blank spaces which included in Earlier Patch Count by DVS
13/10/2016 -- Edited output and remove extra lines by DVS
13/10/2016 -- Change output format to 2 rows for KB by DBI
30/11/2016 -- Fixed issues for Action point and count by DVS
19/01/2016 -- Fixed 0 missing patches by DVS
03/07/2017 -- Removed KB0 and format 2 rows if more than 2 patches missing
'''
import xml.etree.ElementTree as ET
global str
import os
import sys
import re
ip = " "
i = 0
x = " "
count = 0
list = []
ilist = 0
def select_files_in_folder(dir, ext):
    for file in os.listdir(dir):
        if file.endswith('.%s' % ext):
            yield os.path.join(dir, file)

for file in select_files_in_folder(sys.argv[1], 'nessus'):
	tree = ET.parse(file)
	root = tree.getroot()

	for a in root.findall('Report/ReportHost'):
		hostname = ""
		for b in a.getchildren():
			for c in b.getchildren():
				if c.get('name') == "netbios-name":
					hostname = c.text
				elif c.get('name') == "hostname":
					hostname = c.text
				elif c.get('name') == "host-fqdn":
					hostname = c.text
				if c.get("name") == "operating-system":
					osy = c.text

			if b.tag == "ReportItem":
				if "66350" in b.attrib[ 'pluginID' ] or "25197" in b.attrib[ 'pluginID' ]:
					ipaddr = a.attrib[ 'name' ]
					out = b.findtext('plugin_output')
					if ip != ipaddr:
						ip = ipaddr
						for w in out.splitlines():
							if "SSID : " in w:
								ssid = w.split(" ")[2:]
								ssid = " ".join(ssid)
								
								print(ip+" "+"("+hostname+")"+":"+ssid)

