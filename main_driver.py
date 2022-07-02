"""
-=========================================================
Copyright© Centre for Artificial Intelligence and Robotics
Jatin Aggarwal
June 2022

>A small driver program to initiate the data extraction
process from the pcap (packet capture) files.

<-> Dataset used -> /CICDataset/ISCX-VPN-NonVPN-2016/Dataset
VPN datasets only.
-=========================================================
"""

import subprocess as sp
import pyshark
import glob
import os
import statistics as st
import segregate as sg
import get_files_streamcount as gfs
import pandas as pd
import numpy as np
#======================================
#======================================
#=========================================
# Specify the directory and the extension to use the program
directory = '' #please specify the absolute path like -> /home/users/........
extension = "pcap" #by the nature of this project, keep this extension
#=========================================

#=========================================
super_list = [] ## the super list of information (for all files)
#=========================================

files_list = gfs.get_all_files_within_dir(directory, extension)

#==================
### the below code extracts the number of flows in each file methodically
# stream_count_list = gfs.get_stream_count(files_list)
#==================

#Hardcoded stream count list for each of the 14 files for faster processing
stream_count_list = [7, 6, 235, 68, 75, 139, 53, 6, 62, 42, 129, 137, 62, 35]

# print(files_list)
# print(stream_count_list)
# print(len(files_list))
# print(len(stream_count_list))

#These can either be set in a loop
#or, can be specified with each number separately
#depending on the speed of the computer
file_chosen = files_list[12]
stream_count = stream_count_list[12]


flow_info_list_file = []
duration_info_list_file = []
flow_bytes_psec_file = []
flow_packets_psec_file = []
active_times_file = []
idle_times_file = []


# the actual collection of data
for stream_no in range(stream_count):

	flow_info_list = st.get_fwd_rev_flow_iat(file_chosen, stream_no)
	duration_info = st.get_flow_duration(file_chosen, stream_no)
	flow_bytes_psec = st.get_flow_bytes_psec(file_chosen, stream_no)
	flow_packets_psec = st.get_flow_packets_psec(file_chosen, stream_no)
	active_times = st.get_active_info(file_chosen, stream_no)
	idle_times = st.get_idle_info(file_chosen, stream_no)

	flow_info_list_file.append(flow_info_list)
	duration_info_list_file.append(duration_info)
	flow_packets_psec_file.append(flow_packets_psec)
	flow_bytes_psec_file.append(flow_bytes_psec)
	active_times_file.append(active_times)
	idle_times_file.append(idle_times)

info_super_list = []


info_super_list.append(flow_info_list_file)
info_super_list.append(duration_info_list_file)
info_super_list.append(flow_bytes_psec_file)
info_super_list.append(flow_packets_psec_file)
info_super_list.append(active_times_file)
info_super_list.append(idle_times_file)
##=========================================


## Function to write the data into a csv format
def data_to_csv(super_list):
	
	#The actual data segregation
	flow_fwd_rev_iat = info_super_list[0]
	duration_flows = info_super_list[1]
	flow_bytes_psec = info_super_list[2]
	flow_packets_psec = info_super_list[3]
	active_times = info_super_list[4]
	idle_times = info_super_list[5]

# Lists for forward inter arrival time calculations
	fwd_times_min_list = []
	fwd_times_max_list = []
	fwd_times_mean_list =[]
	fwd_times_std_list = []

# Lists for backward inter arrival time calculations
	rev_times_min_list = []
	rev_times_max_list = []
	rev_times_mean_list =[]
	rev_times_std_list = []

# Lists for flow inter arrival time calculations
	flow_times_min_list = []
	flow_times_max_list = []
	flow_times_mean_list =[]
	flow_times_std_list = []
	
# Lists for active times calculations
	active_times_min_list = []
	active_times_max_list = []
	active_times_mean_list =[]
	active_times_std_list = []

# Lists for idle times calculations
	idle_times_min_list = []
	idle_times_max_list = []
	idle_times_mean_list =[]
	idle_times_std_list = []

# Unpacking the super_lists and storing them into smaller lists for
# easier representation of the obtained data
	for tup_list in flow_fwd_rev_iat:
			
		#FORWARD IAT
		fwd_min, fwd_max, fwd_mean, fwd_std = tup_list[0]
		fwd_times_min_list.append(fwd_min)
		fwd_times_max_list.append(fwd_max)
		fwd_times_mean_list.append(fwd_mean)
		fwd_times_std_list.append(fwd_std)

		#BACKWARD IAT
		rev_min, rev_max, rev_mean, rev_std = tup_list[1]
		rev_times_min_list.append(rev_min)
		rev_times_max_list.append(rev_max)
		rev_times_mean_list.append(rev_mean)
		rev_times_std_list.append(rev_std)

		#FLOW IAT
		flow_min, flow_max, flow_mean, flow_std = tup_list[2]
		flow_times_min_list.append(flow_min)
		flow_times_max_list.append(flow_max)
		flow_times_mean_list.append(flow_mean)
		flow_times_std_list.append(flow_std)

# Active times
	for item in active_times:

		active_min, active_max, active_mean, active_std = item
		active_times_min_list.append(active_min)
		active_times_max_list.append(active_max)
		active_times_mean_list.append(active_mean)
		active_times_std_list.append(active_std)

# Idle Times
	for item in idle_times:

		idle_min, idle_max, idle_mean, idle_std = item
		idle_times_min_list.append(idle_min)
		idle_times_max_list.append(idle_max)
		idle_times_mean_list.append(idle_mean)
		idle_times_std_list.append(idle_std)

# The files used are of VPN datasets,
# so by default, we have hardcoded the
# classes as 'VPN'
	classes = ['VPN' for i in range(len(duration_flows))]

# The dictionary which would serve as input to create a pandas DataFrame 
	dict_info = {

	'class' : classes,
	'duration': duration_flows,
	#forward iat
	'fwd_min': fwd_times_min_list,
	'fwd_max': fwd_times_max_list,
	'fwd_mean': fwd_times_mean_list,
	'fwd_std': fwd_times_std_list,
	#backward iat
	'rev_min': rev_times_min_list,
	'rev_max': rev_times_max_list,
	'rev_mean': rev_times_mean_list,
	'rev_std': rev_times_std_list,
	#flow iat
	'flow_min': flow_times_min_list,
	'flow_max': flow_times_max_list,
	'flow_mean': flow_times_mean_list,
	'flow_std': flow_times_std_list,
	#active times
	'active_min': active_times_min_list,
	'active_max': active_times_max_list,
	'active_mean': active_times_mean_list,
	'active_std': active_times_std_list,
	#idle times
	'idle_min': idle_times_min_list,
	'idle_max': idle_times_max_list,
	'idle_mean': idle_times_mean_list,
	'idle_std': idle_times_std_list,
	#flowBytesPsec
	'flow_bytes_psec':flow_bytes_psec,
	#flowPacketsPsec
	'flow_packets_psec':flow_packets_psec,

	}

#pandas -> create the dataframe
	data_f = pd.DataFrame(dict_info)

#pandas -> write to a csv file
	data_f.to_csv("test.csv", mode='a', index=False, header=False)

"""
Calling the data_to_csv function for outputing
the data collected into a csv format
"""
data_to_csv(info_super_list)
