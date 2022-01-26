#!/usr/bin/env python
# # cb_def_export.py
# Version: 1.2
# Created: 01/07/2019
# Updated: 01/10/2019
# Description:
#  Export Carbon Black Defense events.

import argparse
import csv
import re
import string
import sys
from curses.ascii import isprint
from datetime import datetime
from cbapi.defense import CbDefenseAPI
from cbapi.defense.models import Event

c = CbDefenseAPI(profile="default")

# Get difference of al ASCII chars from the set of printable chars
nonprintable = set([chr(i) for i in range(128)]).difference(string.printable)

def printable(text):
	# Use translate to remove all non-printable chars
	return text.translate({ord(character):None for character in nonprintable})

# Function to format epoch time
def convert_time(epoch_time):
    converted_time = datetime.fromtimestamp(int(epoch_time / 1000.0)).strftime(' %b %d %Y %H:%M:%S')
    return converted_time

def convert_start_time(mili_sec):
    convert_start_time = int(mili_sec / 60000)
    return convert_start_time

def print_separated(num):
	return str('{:,}'.format(num).replace(',', ' '))

def main():

	parser = argparse.ArgumentParser(
		prog="cb_def_export.py",
		formatter_class = argparse.RawDescriptionHelpFormatter,
		description = '''
 Python Script that searches CB Defense using the Carbon Black API
 All results are exported as a csv formatted file.
			
 This script requires that Python3 and the CBAPI be installed.

 Avaliable Event Types: *Event Types are Case Sensitive*
 NETWORK, FILE_CREATE, REGISTRY_ACCESS, SYSTEM_API_CALL, CREATE_PROCESS, DATA_ACCESS, INJECT_CODE

 Both Start and End are required to be used together.
		''',
		usage = "%(prog)s [options] [parameters]")
	
	parser.add_argument("-d", "--host_name", 
		required = False,
		metavar = "[Host Name]",
		help = "Query by Device/Computer/Host Name of the Device you are want to export events for")
	parser.add_argument("-s", "--sha256", 
		required = False,
		metavar = "[SHA256Hash]",
		help = "Query for events using the SHA256 hash of a file.")
	parser.add_argument("-a", "--app_name", 
		required = False,
		metavar = "[App Name]",
		help = "Query for events using the Application Name")
	parser.add_argument("-t", "--event_type",
		required = False,
		metavar = "[Event Type]",
		choices=['NETWORK', 'FILE_CREATE', 'REGISTRY_ACCESS', 'SYSTEM_API_CALL', 'CREATE_PROCESS', 'DATA_ACCESS', 'INJECT_CODE'],
		help = "Query for events using Event Type")
	parser.add_argument("-W", "--search_window",
		required = False,
		metavar = "[3h, 1d, 1w, 2w]",
		choices=['3h', '1d', '1w', '2w'],
		help = "Query for events within Search Window")
	parser.add_argument("-S", "--start",
		required = False,
		metavar = "[YYYY-MM-DD]",
		help = "Query for events after Start Date")
	parser.add_argument("-E", "--end",
		required = False,
		metavar = "[YYYY-MM-DD]",
		help = "Query for events before End Date" )

	args = parser.parse_args()

	if args.host_name:
		query = str("hostName:" + str(args.host_name))

		print("Hostname being searched:", file=sys.stderr)
		print("\t"+str(args.host_name), file=sys.stderr)
		
		fname_rename = re.sub(r'/|\\', '_', args.host_name)
		fname = str(fname_rename)+".csv"
	
	if args.sha256:
		query = str("sha256Hash:" + str(args.sha256))
		
		print("Hash being searched:", file=sys.stderr)
		print("\t"+str(args.sha256), file=sys.stderr)
		
		fname = args.sha256 + ".csv"

	if args.app_name:
		query = str("applicationName:" + str(args.app_name))
		
		print("Applicaion name being searched:", file=sys.stderr)
		print("\t"+str(args.app_name), file=sys.stderr)
		
		fname = args.app_name + ".csv"

	if args.event_type:
		query = str("eventType:" + str(args.event_type))
		print("Event Type " + args.event_type + " name being searched:", file=sys.stderr)
		print("\t"+str(args.event_type), file=sys.stderr)
		
		fname = args.event_type + ".csv"

    # Set Variable for Window/Start and End Time
	window = str("searchWindow:" + str(args.search_window))
	start = str("startTime:" + str(args.start))
	end = str("endTime:" + str(args.end))
    
	if args.search_window:
		d = c.select(Event).where(query).and_(window)

	if args.start:
		d = c.select(Event).where(query).and_(start).and_(end)

	print("\nresults obtained " + print_separated(len(d)), file=sys.stderr)    
    
	if int(len(d)) > 0: 
		# Parse and Write CSV File
		with open(fname, 'w', newline='') as csvfile:
		
			cbcsv = csv.writer(csvfile, delimiter=' ', quotechar='|', quoting=csv.QUOTE_MINIMAL)

			#cbcsv.writerow("Timestamp,Hostname,Event Type,Description,Dest. IP,Dest. FQDN,User,File Created,File Created,SHA256,Parent,Parent Commandline,Process Name,Commandline")
			cbcsv.writerow("Timestamp,Hostname,Event_Type,User,Process,PID,Process_CL,Parent,Parent_PID,Parent_CL,Dest_IP,Dest_Port,Src_IP,Src_Port")

			for p in d:

				hostname = str(p.deviceDetails['deviceName'])
				event_time = str(convert_time(p.eventTime))
				eventType = str(p.eventType)
			
				user_name = str(p.processDetails['userName'])
			
				process_name = str(p.processDetails['name'])
				pid = str(p.processDetails['processId'])
				# if p.processDetails['milisSinceProcessStart'] is int:
				# 	process_start = str(convert_time_2(p.processDetails['milisSinceProcessStart']))
				# else:
				# 	process_start = str(p.processDetails['milisSinceProcessStart'])
				process_cl = str(p.processDetails['commandLine'])

				parent_app = str(p.processDetails['parentName'])
				parent_pid = str(p.processDetails['parentPid'])
				patent_cl = str(p.processDetails['parentCommandLine'])

				dest_IP = str(p.netFlow['destAddress'])
				dest_Port = str(p.netFlow['destPort'])
				src_IP = str(p.netFlow['sourceAddress'])
				src_Port = str(p.netFlow['sourcePort'])

				
				# file_created = "N/A"
				# file_created_sha256 = "N/A"
				# if "file_create" in eventType.lower():
				# 	file_created_search = created_regex.search(desc)
				# 	file_created = file_created_search.group()[6:-5]

				# 	if p.targetApp['sha256Hash'] is not None:
				# 		file_created_sha256 = str(p.targetApp['sha256Hash'])

				# user = "N/A"
				# if p.processDetails['userName'] is not None:
				# 	user = str(p.processDetails['userName'])

				# parent = "N/A"
				# if p.processDetails['parentName'] is not None:
				# 	parent = str(p.processDetails['parentName'])

				# process = "N/A"
				# if p.processDetails['name'] is not None:
				# 	process = str(p.processDetails['name'])

				# cmdline = "N/A"
				# if p.processDetails['commandLine'] is not None:
				# 	cmdline = str(p.processDetails['commandLine'])

				# par_cmdline = "N/A"
				# if p.processDetails['parentCommandLine'] is not None:
				# 	par_cmdline = str(p.processDetails['parentCommandLine'])

				# dest_ip = "N/A"
				# if p.netFlow['peerIpV4Address'] is not None:
				# 	dest_ip = str(p.netFlow['peerIpV4Address'])

				# fqdn = "N/A"
				# if p.netFlow['peerFqdn'] is not None:
				# 	fqdn = str(p.netFlow['peerFqdn'])

				cbcsv.writerow(event_time + "," + hostname + "," + eventType + "," + user_name \
					  + "," + process_name + "," + pid + "," + process_cl + "," + parent_app \
					  + "," + parent_pid + "," + patent_cl + "," + dest_IP + "," + dest_Port \
					  + "," + src_IP + "," + src_Port)

		# Cleanup CSV file to make it easier to read
		text = open(fname, "r")
		text = ''.join([i for i in text]) \
   			.replace(" ", "") \
			.replace("||", " ")
		x = open(fname,"w")
		x.writelines(text)
		x.close()

if __name__ == '__main__':
	main()
