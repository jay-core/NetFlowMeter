"""
-=========================================================
Copyright© Centre for Artificial Intelligence and Robotics
Jatin Aggarwal
June 2022

>An important file which contains the function for segregating
flows into the direction forward and backward.

>forward packets are decided on the direction of the first arriving
packet in the flow (src and dst ip addresses)

>backward packets will have the opposite values of the src and dst
ip address.

>The segregation is important in calculation of the forward, backward
and the flow inter arrival times in the statistics.py file

<-> Dataset used -> /CICDataset/ISCX-VPN-NonVPN-2016/Dataset
VPN datasets only.
-=========================================================
"""
import subprocess as sp
import os

import pyshark
import numpy as np
import statistics as st

#=========================================
#=========================================

def seg_flow_pkts(file, stream_no):
	"""
	Takes a file and the stream number of and returns a list containing 
	fwd and back packets,

	param: file, total_flows

	return: list of list of fwd and back pkts
	"""
	# The tshark command to extract the flows and their parameters -> time_relative
	command = 'tshark -r {} -Y "tcp.stream eq {}" -T fields -e ip.src -e ip.dst -e frame.time_relative -E separator=,'.format(file, stream_no)
	out = sp.getoutput(command)

	flow_list = out.split("\n")
	fwd_ip_src, fwd_ip_dst, time = flow_list[0].split(',')
	rev_ip_src, rev_ip_dst = (fwd_ip_dst, fwd_ip_src)

	fwd_pkt_list = []
	rev_pkt_list = []

	for tup in flow_list:
		ip1, ip2, time = tup.split(',')
		# pos = flow_list.index(tup)
		if ip1 == fwd_ip_src:
			fwd_pkt_list.append(tup)
		if ip1 == rev_ip_src:
			rev_pkt_list.append(tup)

	super_list = [fwd_pkt_list, rev_pkt_list]
	
	return super_list
#=========================================
