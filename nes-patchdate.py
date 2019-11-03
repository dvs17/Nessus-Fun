#!/usr/bin/python3.6
'''
Nessus extractor for all the issues in directory including cvss score, title and plugin
created by dvs

Usage:
python issuex.py [Directory Nessus files are stored]
'''
import xml.etree.ElementTree as ET
global str
import os
import sys
import re
from decimal import Decimal
ip = " "
v = " "
some = []
x = 0
def select_files_in_folder(dir, ext):
    for file in os.listdir(dir):
        if file.endswith('.%s' % ext):
            yield os.path.join(dir, file)
for file in select_files_in_folder(sys.argv[1], 'nessus'):
	tree = ET.parse(file)
	root = tree.getroot()

	for a in root.findall('Report/ReportHost'):
		for b in a.getchildren():
			if b.tag == "ReportItem":
				vulname = b.get('pluginName')
				cvss = b.findtext('cvss_base_score')
				patch = b.findtext('patch_publication_date')
				if patch is not None:
					issues = vulname+"\t"+str(patch)
					print(issues)
