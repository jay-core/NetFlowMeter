"""
-=========================================================
Copyright© Centre for Artificial Intelligence and Robotics
Jatin Aggarwal
June 2022

>The python file which uses the glob module to extract all 
files within a directory with a specific pattern(here,
the pattern would be '.pcap')

<-> Dataset used -> /CICDataset/ISCX-VPN-NonVPN-2016/Dataset
VPN datasets only.
-=========================================================
"""
import numpy as np
import subprocess as sp
import os
import glob
import statistics as st
#=========================================
#=========================================

def get_all_files_within_dir(directory, extension):
	"""
	Takes input as the directory name with trailing '/' and the
	extension and returns the list of files in the current 
	directory with the specified extension

	param: directory and the extension

	return = the list of all the files with the 
	specified extension
	"""
	glob_command = directory + '*' + '.' + extension
	# print(glob_command)

	files = glob.glob(glob_command)
	files_list = sorted(files)

	return files_list
#=========================================

def get_stream_count(files_list):
	"""
	Takes input a file list and returns the list containing
	all the stream counts for all the files in the input
	file list

	param: list of pcap files

	return: list containing stream counts for all the files
	"""

	stream_count_list = []

	for file in files_list:
		flow_count = st.get_total_flows(file)
		stream_count_list.append(flow_count)

	return stream_count_list

#=========================================