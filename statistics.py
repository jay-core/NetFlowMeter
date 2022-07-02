"""
-=========================================================
Copyright© Centre for Artificial Intelligence and Robotics
Jatin Aggarwal
June 2022

<-> Dataset used -> /CICDataset/ISCX-VPN-NonVPN-2016/Dataset
VPN datasets only.

>The collection of statistical functions for the extraction of 
features from the packet capture files.

>mainly, the wireshark command line tool <tshark> has been used to extract flows and
collecting them into lists. For more information on tshark, see the tshark documentation
page -> https://www.wireshark.org/docs/man-pages/tshark.html

>subprocess module helps in getting the string data from the command line commands
and storing it into lists for further processing.

==The available features (as of June 2022) are as follows-

1. total flows -> the total number of flows/streams in the given pcap file
2. total flow duration -> the duration in which the flow was active
3. total bytes -> the total bytes transfered between the src and dst in a flow
4. total packets -> the total number of packets transfered in a flow
5. forward_iat -> the interarrival times of the forward direction packets
6. backward_iat -> the interarrival times of the reverse direction packets
7. flow_iat -> the interarrival times for the flow packets
8. active_times -> The time a flow was active before going idle
9. idle_times -> the time a flow was idle before becoming active
10. flow_bytes_psec -> the rate of flow of bytes in a flow
11. flow_packets_psec -> the rate of flow of packets in a flow

The points 5 to 9 have additional metrics -> min, max, mean, std(standard deviation),
which add up to 23 total features, that can be used for further processing, analysing
or for machine learning purposes.
-=========================================================
"""
import numpy as np
# import pandas as pd

import subprocess as sp
# import pyshark
import segregate as seg
#=========================================
#=========================================

##========================================
#=============--CONSTANTS--===============
CLUMP_TIMEOUT = 1
ACTIVE_TIMEOUT = 0.005
##========================================

def get_total_flows(pcapfile):
	"""
	Gives the total number of flows in a pcapfile. Only the flows count,
	not the flows themselves.
	
	param: The pcap file to parse
	return: (int) The number of flows/streams
	"""

	command = 'tshark -qz conv,tcp -r {} | wc -l'.format(pcapfile)
	flows = sp.getoutput(command)

	return (int(flows) - 6)
#=========================================

def get_flow_duration(file, stream_no):
	"""
	returns the flow_duration for the file and the stream number

	param: file, stream number

	return: (float) duration of the flow
	"""

	#Flow duration
	command = 'tshark -r {} -Y "tcp.stream eq {}" -T fields -e frame.time_relative'.format(file, stream_no)
	temp_str = sp.getoutput(command)

	dur_list = temp_str.split('\n')
	time1 = float(dur_list[0])
	time2 = float(dur_list[-1])

	duration = time2 - time1

	return duration
#=========================================

def get_flow_bytes(file, stream_no):
	"""
	returns the flow_bytes for the file and the stream number

	param: file, stream number

	return: (float) total bytes in the flow
	"""

	# total flow bytes
	command = 'tshark -r {} -Y "tcp.stream eq {}" -T fields -e frame.len'.format(file, stream_no)
	temp_str = sp.getoutput(command)

	bytes_list = temp_str.split('\n')
	acc = 0
	for item in bytes_list:
		acc += int(item)

	return acc
#=========================================

def get_flow_packets(file, stream_no):
	"""
	returns the flow_packets for the file and the stream number

	param: file, stream number

	return: (float) total packets in the flow
	"""

	command = 'tshark -r {} -Y "tcp.stream eq {}" -T fields -e frame.len | wc -l'.format(file, stream_no)
	temp_str = sp.getoutput(command)

	return int(temp_str)
#=========================================

def get_fwd_rev_flow_iat(file, stream_no):
	"""
	Takes input as the file and the stream number to follow and
	returns the list containing the statistics like min, max, 
	mean and std of the fwd, rev and flow iats

	param: file and the stream number

	return: list containing tuples of [(fwd), (rev), (flow)], where each ()
	has min, max, mean and std

	"""

	super_list = seg.seg_flow_pkts(file, stream_no)

	fwd = super_list[0]
	rev = super_list[1]

	fwd_list = []
	rev_list = []

	for i in fwd:
		s, d, time = i.split(',')
		fwd_list.append(float(time))

	for i in rev:
		s, d, time = i.split(',')
		rev_list.append(float(time))

	fwd_iat_list = [t-s for s,t in zip(fwd_list, fwd_list[1:])]
	rev_iat_list = [t-s for s,t in zip(rev_list, rev_list[1:])]

	flow_iat_list = []
	for (f,r) in zip(fwd_list, rev_list):
		flow_iat_list.append(f-r)


	#-----Forward packets iat stats
	fwd_min_iat = 0
	fwd_max_iat = 0
	fwd_mean_iat = 0
	fwd_std_iat = 0


	#-----Backward packets iat stats
	rev_min_iat = 0
	rev_max_iat = 0
	rev_mean_iat = 0
	rev_std_iat = 0


	#-----Flow packets iat stats
	flow_min_iat = 0
	flow_max_iat = 0
	flow_mean_iat = 0
	flow_std_iat = 0


	fwd_min_iat = min(fwd_iat_list, default=0)
	fwd_max_iat = max(fwd_iat_list, default=0)
	if(len(fwd_iat_list) == 0):
		fwd_mean_iat = 0
		fwd_std_iat = 0
	else:
		fwd_mean_iat = np.mean(fwd_iat_list)
		fwd_std_iat = np.std(fwd_iat_list)

	
	rev_min_iat = min(rev_iat_list, default=0)
	rev_max_iat = max(rev_iat_list, default=0)
	if(len(rev_iat_list) == 0):
		rev_mean_iat = 0
		rev_std_iat = 0
	else:
		rev_mean_iat = np.mean(rev_iat_list)
		rev_std_iat = np.std(rev_iat_list)


	flow_min_iat = min(flow_iat_list, default=0)
	flow_max_iat = max(flow_iat_list, default=0)
	flow_mean_iat = np.mean(flow_iat_list)
	flow_std_iat = np.std(flow_iat_list)


	fwd_info = (fwd_min_iat, fwd_max_iat, fwd_mean_iat, fwd_std_iat)
	rev_info = (rev_min_iat, rev_max_iat, rev_mean_iat, rev_std_iat)
	flow_info = (flow_min_iat, flow_max_iat, flow_mean_iat, flow_std_iat)

	flow_info_list = [fwd_info, rev_info, flow_info]


	return flow_info_list
#=========================================

def get_flow_bytes_psec(file, stream_no):
	"""
	Takes input file and the stream number and returns
	the rate of flow of bytes in the stream

	flowbps = total bytes in the flow / duration of the flow

	param: file and the stream number

	return: the flowbytespsec for the particular flow
	"""

	duration = get_flow_duration(file, stream_no)
	total_bytes = get_flow_bytes(file, stream_no)

	return (float(total_bytes)/float(duration))
#=========================================

def get_flow_packets_psec(file, stream_no):
	"""
	Takes input file and the stream number and returns
	the rate of flow of packets in the stream

	flowbps = total packets in the flow / duration of the flow

	param: file and the stream number

	return: the flowpktspsec for the particular flow
	"""

	duration = get_flow_duration(file, stream_no)
	total_packets = get_flow_packets(file, stream_no)

	return (float(total_packets)/float(duration))
#=========================================

def get_active_info(file, stream_no):
	"""
	Takes input as the file and the stream to follow and
	returns the tuple of (min, max, mean, std) for the active
	times of the flow

	param: file and the stream number

	return: the tuple(min, max, mean, std) 
	"""

	command = 'tshark -r {} -Y "tcp.stream eq {}" -T fields -e frame.time_relative'.format(file, stream_no)
	temp_str = sp.getoutput(command)
	flow_str = temp_str.split('\n')

	active_times_list = []

	flow_times = []
	for string in flow_str:
		flow_times.append(float(string))

	start_active = 0
	last_active = 0
	last_timestamp = flow_times[0]

	for index in range(len(flow_times)):
		try:
			current_time = flow_times[index + 1] - last_timestamp
			
			if flow_times[index + 1] - last_timestamp > CLUMP_TIMEOUT:
				
				if current_time > ACTIVE_TIMEOUT:
					duration = abs(last_active - start_active)
					if duration >= 0:	
						active_times_list.append(current_time - last_active)

					last_active = current_time
					start_active = current_time
			else:
				last_active = current_time

			last_timestamp = flow_times[index + 1]
		except:
			active_times_list.append(0)

    #==========
	active_time_min = min(active_times_list)
	active_time_max = max(active_times_list)
	active_time_mean = np.mean(active_times_list)
	active_time_std = np.std(active_times_list)

	return(active_time_min, active_time_max, active_time_mean, active_time_std)

#=========================================


def get_idle_info(file, stream_no):
	"""
	Takes input as the file and the stream to follow and
	returns the tuple of (min, max, mean, std) for the idle
	times of the flow

	param: file and the stream number

	return: the tuple(min, max, mean, std) 
	"""

	##==============
	command = 'tshark -r {} -Y "tcp.stream eq {}" -T fields -e frame.time_relative'.format(file, stream_no)
	temp_str = sp.getoutput(command)
	flow_str = temp_str.split('\n')

	idle_times_list = []

	flow_times = []
	for string in flow_str:
		flow_times.append(float(string))

	last_active = 0
	last_timestamp = flow_times[0]

	for index in range(len(flow_times)):
		try:
			current_time = flow_times[index + 1] - last_timestamp
			if flow_times[index + 1] - last_timestamp > CLUMP_TIMEOUT:
				if current_time > ACTIVE_TIMEOUT:	
					idle_times_list.append(current_time - last_active)
					last_active = current_time
				
			else:
				idle_times_list.append(0)
				last_active = current_time

			last_timestamp = flow_times[index + 1]
		except:
			continue

    #==========
	idle_time_min = min(idle_times_list)
	idle_time_max = max(idle_times_list)
	idle_time_mean = np.mean(idle_times_list)
	idle_time_std = np.std(idle_times_list)

	return(idle_time_min, idle_time_max, idle_time_mean, idle_time_std)

#=========================================
