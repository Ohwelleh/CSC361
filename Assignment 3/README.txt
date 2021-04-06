This program was developed to run on Python 3 and must use the following command for execution. If not, unexpected behaviour may occur.

	python3 AnalysisIP.py < .pcap file >

AnalysisIP.py will read the passed pcap file and output the following related to UDP and ICMP packets:

IP address of the source node.
IP address of the ultimate destination.
IP addresses of the intermediate destination nodes.
Values in the protocol field of IP headers. (UDP and/or ICMP only)
Number of fragments created. (0 if none)
Offset of last fragment. (0 if none)
Average and standard derivation (s.d) RTT between source and all intermediate nodes and ultimate destination.

=================================================

Example output of a non-fragmented pcap file:

The IP address of the source node: 192.168.100.17
The IP address of ultimate destination node: 8.8.8.8
The IP addresses of the intermediate destination nodes:
	router 1: 142.104.68.167
	router 2: 142.104.68.1
	router 3: 192.168.9.5

The values in the protocol field of IP headers:
	17: UDP
	1: ICMP

The number of fragments created from the original datagram is: 0
The offset of the last fragment is: 0

The avg RTT between 192.168.100.17 and 142.104.68.167 is: 11.214 ms, the s.d. is: 0.221054 ms
The avg RTT between 192.168.100.17 and 142.104.68.1 is: 15.712667 ms, the s.d. is: 0.570675 ms
The avg RTT between 192.168.100.17 and 192.168.9.5 is: 15.420667 ms, the s.d. is: 0.209438 ms
The avg RTT between 192.168.100.17 and 8.8.8.8 is: 19.648667 ms, the s.d. is: 3.319851 ms

=================================================

Example output of a fragmented pcap file:

The IP address of the source node: 192.168.0.108
The IP address of ultimate destination node: 4.2.2.2
The IP addresses of the intermediate destination nodes:
	router 1: 142.104.69.243
	router 2: 142.104.68.1
	router 3: 192.168.9.5

The values in the protocol field of IP headers:
	17: UDP
	1: ICMP

The number of fragments created from the original datagram 21908 is: 2
The offset of the last fragment is: 1480

The avg RTT between 192.168.0.108 and 142.104.69.243 is: 9.441833 ms, the s.d. is: 5.108984 ms
The avg RTT between 192.168.0.108 and 142.104.68.1 is: 17.605667 ms, the s.d. is: 0.214366 ms
The avg RTT between 192.168.0.108 and 192.168.9.5 is: 18.387333 ms, the s.d. is: 0.202918 ms
The avg RTT between 192.168.0.108 and 4.2.2.2 is: 29.0645 ms, the s.d. is: 1.133342 ms