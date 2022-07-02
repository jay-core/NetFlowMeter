# NetFlowMeter
A network-packet dissector, implemented in python, which can be used for feature extraction or general network packet analysis with available features like packet size, packet times, flow bytes/packets etc.

<-> Dataset used -> /CICDataset/ISCX-VPN-NonVPN-2016/Dataset
VPN datasets only.

>mainly, the wireshark command line tool <tshark> has been used to extract flows and
collecting them into lists. For more information on tshark, see the tshark documentation
page -> https://www.wireshark.org/docs/man-pages/tshark.html

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
  
The project is simply implemented in python and to use this, please add the necessary .pcap files in the directory and then change the class of the network traffic accordingly.
  
