#!/usr/bin/python3.5m
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

