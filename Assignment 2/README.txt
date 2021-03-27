This program was developed to run on Python 3 and must use the following command for execution. If not, unexpected behaviour may occur.

		python3 TCPAnalyze.py <A .cap file>

TCPAnalyze.py will read a capture file and output the following example:

Connection 1:
Source Address: 192.168.1.164
Destination Address: 142.104.5.64
Source Port: 1200
Destination Port: 80
Status: S2F1/R
(This lower section only appears if the connection was complete)
Start Time: 0 seconds
End Time: 43.612948 seconds
Duration: 43.612948 seconds
Number of packets sent from Source to Destination: 54 packets
Number of packets sent from Destination to Source: 77 packets
Total number of packets: 131 packets
Number of data bytes sent from Source to Destination: 3063 bytes
Number of data bytes sent from Destination to Source: 100545 bytes
Total number of bytes: 103608 bytes
END

For each TCP connection of the capture file. Next the following sections will be output after all the connection details have been output.

C) General:

Total number of complete TCP connections: 32
Number of reset TCP connections: 34
Number of TCP connections that were still open when the trace capture ended: 16

-----------------------------------------------------------------

D) Complete TCP Connections:

Minimum time duration: 0.010284 seconds
Mean time duration: 6.812052 seconds
Maximum time duration: 43.612948 seconds

Minimum RTT value: 0.002269
Mean RTT value: 0.039433
Minimum RTT value: 0.159684

Minimum number of packets including both send/received: 8 packets
Mean number of packets including both send/received: 37.3125 packets
Maximum number of packets including both send/received: 239 packets

Minimum receive window size including both send/received: 0 bytes
Mean receive window size including both send/received: 15277.688442 bytes
Maximum receive window size including both send/received: 64240 bytes

-----------------------------------------------------------------
