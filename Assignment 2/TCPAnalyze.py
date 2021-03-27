'''

        CSC 361: Computer Communications and Networks
        Programming Assignment 2: TCP Traffic Analysis
                    Prof: Kui Wu
            Developed By: Austin Bassett

'''

# Modules
import sys
import struct

def processPackets(rawData):
    """
    Processes the rawData into PacketObjects which contain the necessary information for each object and creates a unique list containing all the connections
    going from the source to the destination.

    Parameters
    ----------
    rawData: list
        A list were each entry is one byte.

    Returns
    -------
    processedPacket
        A list of packetObjects.

    tcpTuples
        A unique list of all the connections going from Source to Destination. Each entry is in the following tuple format:
        (Source IP, Source Port, Destination Port, Destination IP)
    """
    
    # Variables
    headerBytes = 16 
    processedPacket = [] 
    packetNumber = 1 
    rawTCPTuples = [] 
    tcpTuples = [] 
    
    # Variables for tracking the remaining bytes from the pcap file.
    totalBytesLeft = len(rawData)
    timeAdjuster = 0

    # Loop for processing packet headers and packet data.
    while totalBytesLeft > 0:

        # Initializing a packet object.
        packetObject = packet()

        # Extracting the header bytes.
        rawHeaderData = rawData[:headerBytes]

        # Removing the header bytes and ethernet bytes from the rawData list.
        removeBytes = headerBytes 
        rawData = rawData[removeBytes:]

        # Process packet header data.
        processHeader(rawHeaderData, packetObject)

        # Retreving the length of the data packet.
        dataLength = packetObject.packetDataLength

        # Extracting the packet bytes.
        rawPacketData = rawData[:dataLength]

        # Removing the packet bytes from the rawData list.
        rawData = rawData[dataLength:]

        # Process packet data.
        processPacketData(rawPacketData, packetObject)

        # Add the packet object to the list of packets.
        processedPacket.append(packetObject)

        # Calculate how many bytes are left in the rawData list.
        totalBytesLeft = totalBytesLeft - headerBytes - dataLength

        # Retreving the values needed for the TCP 4-tuple.
        tupleSrcIP = packetObject.IP_header.src_ip
        tupleDstIP = packetObject.IP_header.dst_ip
        tupleSrcPort = packetObject.TCP_header.src_port
        tupleDstPort = packetObject.TCP_header.dst_port

        packetTuple = (tupleSrcIP, tupleSrcPort, tupleDstPort, tupleDstIP)

        # Adjusting the time stamp of each packet.
        if packetNumber == 1:

            # Retreving the timestamp of the first packet to adjust all other packet timestamps.
            timeAdjuster = round(packetObject.timestamp, 6)

            # Setting the time of first packet to 0.
            packetObject.timestamp = round(0,6)
        
        else:
            
            # Calculating the time of the packet relative to the pcap file.
            relativeTimestamp = packetObject.timestamp - timeAdjuster

            # Setting the packets new timestamp.
            packetObject.timestamp = round(relativeTimestamp, 6)

        # Storing the tuple in a list.
        rawTCPTuples.append(packetTuple)
        packetNumber = packetNumber + 1

    # Creating a list that contains only the Sources -> Destination Tuples, so removing the tuples going Destination -> Source.
    seen = set()
    for tup in rawTCPTuples:
        tup = tuple(tup)
        if tup not in seen and tuple(reversed(tup)) not in seen:
            seen.add(tup)
            tcpTuples.append(tup)

    # Removing duplicates.
    tcpTuples = list(set(tcpTuples))

    # Sorting the list based on Source port in ascending order.
    tcpTuples.sort(key=lambda tup: tup[1])  

    # Return the processed data.
    return processedPacket, tcpTuples

def processHeader(rawHeaderData, packetPointer):
    """
    Extracts the seconds, microseconds and length of the packet's data and then stores these values in the passed packetObject.

    Parameters
    ----------
    rawHeaderData: list
        A list containing the bytes related to packet's header.

    packetPointer: packet
        A pointer to a packetObject
    """
    
    # Creating the binary strings.
    seconds = b''.join([byte for byte in rawHeaderData[:4]])
    microSeconds = b''.join([byte for byte in rawHeaderData[4:8]])
    packetDataLength = b''.join([byte for byte in rawHeaderData[8:12]])

    # Saving the timestamp and the data length of the packet.
    packetPointer.timestamp_set(seconds, microSeconds, 0)
    packetPointer.packetDataLengthSet(packetDataLength)
    

def processPacketData(rawPacketData, packetPointer):
    """
    Extacts the information about the packet from the rawPacketData and stores the results in the passed packetObject.
    The following list is what information is extracted about each packet:
    
    - IP Header Length, IP Total Length, IP Source & Destination Addresses and Ports
    - Sequence Number, Acknowledgment Number, TCP Data Offset, TCP Flags
    - Window size

    Parameters
    ----------
    rawPacketData: list
        A list containing the bytes related to packet's data.

    packetPointer: packet
        A pointer to a packetObject
    """

    # Setting IP length.
    packetPointer.IP_header.set_header_len(rawPacketData[14])

    # Offset variables for adjusting byte locations.
    ethernetOffset = 14
    headerIPOffset = packetPointer.IP_header.ip_header_len + ethernetOffset

    # Creating the Total length byte string.
    totalLen = b''.join([byte for byte in rawPacketData[ (ethernetOffset + 2) : (ethernetOffset + 4)]])

    # Creating the Source and Destination byte strings.
    sourceAddress = b''.join([byte for byte in rawPacketData[ (ethernetOffset + 12 ) : (ethernetOffset + 16) ]])
    destinationAddress = b''.join([byte for byte in rawPacketData[ (ethernetOffset + 16) : (ethernetOffset + 20) ]])
    sourcePort = b''.join([byte for byte in rawPacketData[headerIPOffset:(headerIPOffset + 2)]])
    destinationPort = b''.join([byte for byte in rawPacketData[(headerIPOffset + 2):(headerIPOffset + 4)]])

    # Creating the Sequence number and Acknowledgment number byte strings.
    sequenceNumber = b''.join([byte for byte in rawPacketData[(headerIPOffset + 4):(headerIPOffset + 8)]])
    ackNumber = b''.join([byte for byte in rawPacketData[(headerIPOffset + 8):(headerIPOffset + 12)]])

    # Creating the Data Offset and Flag byte strings.
    dataOffsetTCP = b''.join([byte for byte in rawPacketData[(headerIPOffset + 12):(headerIPOffset + 13)]])
    flags = b''.join([byte for byte in rawPacketData[(headerIPOffset + 13):(headerIPOffset + 14)]])

    # Creating the Window size byte strings.
    windowSize1 = b''.join([byte for byte in rawPacketData[(headerIPOffset + 14):(headerIPOffset + 15)]])
    windowSize2 = b''.join([byte for byte in rawPacketData[(headerIPOffset + 15):(headerIPOffset + 16)]])

    # Setting the Total Length.
    packetPointer.IP_header.set_total_len(totalLen)

    # Setting the Source and Destination values.
    packetPointer.IP_header.set_IP(sourceAddress, destinationAddress)

    sourcePort = struct.unpack('BB', sourcePort)
    destinationPort = struct.unpack('BB', destinationPort)

    packetPointer.TCP_header.set_src_port(sourcePort)
    packetPointer.TCP_header.set_dst_port(destinationPort)

    # Setting the Sequence and Ack number.
    packetPointer.TCP_header.set_seq_num(sequenceNumber)
    packetPointer.TCP_header.set_ack_num(ackNumber)

    # Setting the Data Offset, Flags, and Window size.
    packetPointer.TCP_header.set_data_offset(dataOffsetTCP)
    packetPointer.TCP_header.set_flags(flags)
    packetPointer.TCP_header.set_window_size(windowSize1, windowSize2)

def processConnections(packetPointerList, TCPTuples):
    """
    Process the packets related to each connection and calculating the following information for each connection:
    
    - Completed Connections, Open Connections, Total Connections
    - Bytes and Number of Packets sent from Source to Destination
    - Bytes and Number of Packets sent from Destination to Source
    - Each packets Window size

    Parameters
    ----------
    packetPointerList: list
        A list containing all the processed packetObjects.

    TCPTuples: list
        A list containing all the unique connection tuples.
    """
    
    # Variables for tracking Total, Complete, and Open connections. Also, the connection number for output.
    totalConnections = len(TCPTuples)
    completedConnections = 0
    openConnections = 0
    connectionNumber = 1

    # Lists for tracking the statistics of completed TCP connections.
    statsTimeDuration = []
    statsRTTValue = []
    statsNumberOfPackets = []
    statsWindowSize = []
    statsTotalRST = []

    # Output total connections.
    print(f'A) Total number of connections: {totalConnections}')
    print('-----------------------------------------------------------------')
    print()

    # Iteratate over each connection.
    print('B) Connections\' details:')
    print()
    for connection in TCPTuples:
        
        # Connection packet trackers.
        connectionPackets = []
        packetWindowSizes = []
        clientPackets = []
        serverPackets = []
        packetSrcToDst = 0
        packetDstToSrc = 0

        # Connection end time tracker.
        endTime = 0

        # Connection flag trackers.
        synTracker = 0
        finTracker = 0
        rstTracker = 0

        # Connection byte trackers.
        totalDataByte = 0
        srcToDstBytes = 0
        dstToSrcBytes = 0

        # Connection boolean variables.
        connectionComplete = False
        firstPacket = True

        # Reversing the connection tuple to find packets going Destination -> Source.
        reversedConnection = tuple(reversed(connection))

        # Exract the matching packets.
        for packet in list(packetPointerList):

            # Retreving the Source and Destination information.
            tupleSrcIP = packet.IP_header.src_ip
            tupleDstIP = packet.IP_header.dst_ip
            tupleSrcPort = packet.TCP_header.src_port
            tupleDstPort = packet.TCP_header.dst_port

            # Creating the packet tuple.
            tempTuple = (tupleSrcIP, tupleSrcPort, tupleDstPort, tupleDstIP)

            # Checking if packet matches connection
            if tempTuple == connection or tempTuple == reversedConnection:

                # Add packet to connection packet list & remove the packet from the packetPointer list.
                connectionPackets.append(packet)
                packetPointerList.remove(packet)

        # Retreving the Source and Destination addresses.
        clientAddress = connectionPackets[0].IP_header.src_ip
        serverAddress = connectionPackets[0].IP_header.dst_ip
        clientPort = connectionPackets[0].TCP_header.src_port
        serverPort = connectionPackets[0].TCP_header.dst_port

        # Initializing the start time of the connection to be the timestamp of the first packet.
        startTime = connectionPackets[0].timestamp

        # Iterate over all the packets of the connection.
        for packet in connectionPackets:

            # Extracting the data of each connection related packet.
            packetResults = connectionRelatedPackets(packet, clientAddress, packetWindowSizes, clientPackets, serverPackets)

            # Update the byte trackers.
            srcToDstBytes = srcToDstBytes + packetResults[0]
            dstToSrcBytes = dstToSrcBytes + packetResults[1]
            totalDataByte = totalDataByte + packetResults[2]

            # Update packets sent trackers.
            packetSrcToDst = packetSrcToDst + packetResults[3]
            packetDstToSrc = packetDstToSrc + packetResults[4]

            # Update flag trackers.
            synTracker = synTracker + packetResults[5]
            finTracker = finTracker + packetResults[6]
            rstTracker = rstTracker + packetResults[7]

            # Check if end time needs to be updated.
            if endTime < packetResults[8]:
                endTime = packetResults[8]
        
        # Checking if the connection completed.
        if synTracker >= 1 and finTracker >= 1:
            connectionComplete = True

            # Update complpeted connections tracker.
            completedConnections = completedConnections + 1

        # Creating a list with the basic information each connection will output, regardless of complete or not.
        basicInfo = [connectionNumber, clientAddress, serverAddress, clientPort, serverPort, synTracker, finTracker]

        # Output the basic connection information.
        basicConnectionDetails(basicInfo, rstTracker, statsTotalRST)

        # If connection wasn't complete, go to next connection.
        if not connectionComplete:
            
            # Tracking the open connections.
            openConnections = openConnections + 1

            # Change the last output line of Connection Details if this is the last connection.
            if connectionNumber == totalConnections:
                print('END')
                print('\n-----------------------------------------------------------------')
        
            else:
                print('END')
                print('+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')

            # Update connection number.
            connectionNumber = connectionNumber + 1

            continue
        
        # Total packets sent.
        totalPackets = len(connectionPackets)
        statsNumberOfPackets.append(totalPackets)

        # Calculate Round Trip Time (RTT) of packets for completed connections.
        rttCalculations(clientPackets, serverPackets, statsRTTValue)

        # Adding the completed connection window sizes to stats list.
        statsWindowSize.extend(packetWindowSizes)

        # Calculating time duration
        durationTime = round((endTime - startTime), 6)
        statsTimeDuration.append(durationTime)

        # Lists for connection details.
        timeInfo = [startTime, endTime, durationTime]
        packetInfo = [packetSrcToDst, packetDstToSrc, totalPackets]
        byteInfo = [srcToDstBytes, dstToSrcBytes, totalDataByte]

        # Output the details of a completed connection.
        completedConnectionDetails(timeInfo, packetInfo, byteInfo, connectionNumber, totalConnections)

        # Update connection number.
        connectionNumber = connectionNumber + 1

    # Output the General Section Information.
    generalConnectionOutput(completedConnections, statsTotalRST, openConnections)

    # Ouput Complete TCP Connection Section Information.
    completeTCPConnectionsOutput(statsTimeDuration, statsNumberOfPackets, statsWindowSize, statsRTTValue)


def connectionRelatedPackets(packet, clientAddress, packetWindowSizes, clientPackets, serverPackets):
    """
    Extracts the following information about a packet:
    - Total bytes sent, which direction they were sent from
    - Which flag bits were set.

    Parameters
    ----------
    packet: packet
        A packetObject containing information about a packet.

    clientAddress: str
        The source IP address.
    
    packetWindowSizes: list
        A list for storing the window size of the packet.
    
    clientPackets: list
        A list for storing the packets going from Source -> Destination

    serverPackets: list
        A list for storing the packets going from Destination -> Source

    Returns
    -------
    The following list: srcToDstBytes, dstToSrcBytes, packetBytes, packetSrcToDst, packetDstToSrc, synTracker, finTracker, rstTracker, endTime
    """

    # Tracking the bytes sent between the Source(Client) and Destination(Server).
    packetBytes = 0
    srcToDstBytes = 0
    dstToSrcBytes = 0

    # Tracking the packets sent between the Source(Client) and Destination(Server).
    packetSrcToDst = 0
    packetDstToSrc = 0

    # Tracking the flags of each packet.
    synTracker = 0
    finTracker = 0
    rstTracker = 0

    # Tracking the end time.
    endTime = 0
            
    # Retreving the packet's IP Total Length, IP Header Length and TCP Header Length.
    totalLength = packet.IP_header.total_len
    ipHeaderLength = packet.IP_header.ip_header_len
    tcpHeaderLength = packet.TCP_header.data_offset
        
    # Adding the packets window size to the Window Size stat.
    packetWindowSizes.append(packet.TCP_header.window_size)

    # Calculating the bytes being sent (Ignoring padding).
    packetBytes = totalLength - ipHeaderLength - tcpHeaderLength
    packet.setPayload(packetBytes)

    # Checking if current packet is sending bytes to the client or the server.
    if packet.IP_header.src_ip == clientAddress:
            
        # Storing the total bytes sent from Source to Destination.
        srcToDstBytes = packetBytes

        # Indicating this packet was sent from Source to Destination.
        packetSrcToDst = 1

        # Store packet in client packet list for RTT calculations.
        clientPackets.append(packet)

    else:

        # Storing the total bytes sent from Destination to Source.
        dstToSrcBytes = packetBytes

        # Indicating this packet was sent from Destination to Source.
        packetDstToSrc = 1

        # Store packet in server packet list for RTT calculations.
        serverPackets.append(packet)

    # Checking if SYN, FIN, or RST bit were set.
    if packet.TCP_header.flags["SYN"] == 1:
        synTracker = 1
        
    if packet.TCP_header.flags["FIN"] == 1:
        finTracker = 1

        # Update end time, as this might be the last FIN packet of the connection.
        endTime = packet.timestamp

    if packet.TCP_header.flags["RST"] == 1:
        rstTracker = 1

    # Creating a list containing all the results.
    results = [srcToDstBytes, dstToSrcBytes, packetBytes, packetSrcToDst, packetDstToSrc, synTracker, finTracker, rstTracker, endTime]

    return results


def rttCalculations(clientPackets, serverPackets, statsRTTValue):
    """
    Calculates the Round Trip Time (RTT) of packets from Client -> Server -> Client for each connection.

    Parameters
    ----------
    clientPackets: list
        A list containing all the packetObjects sent from the client side.

    serverPackets: list
        A list containing all the packetObjects sent from the server side.

    statsRTTVaue: list
        A list for storing the calculated RTT values.
    """

    # List previously seen ACK Values.
    seenACKValues = []

    # For each client packet see if there is a matching ACK value in server packet.
    for cPack in clientPackets:

        # Checking if this packet is the first or last one sent to server to establish/close a connection.
        packetSYNorFIN = False
        if cPack.TCP_header.flags["SYN"] == 1 or cPack.TCP_header.flags["FIN"] == 1:

            # Calculating the ACK value we are looking for.
            ackValue = cPack.TCP_header.seq_num + 1
            packetSYNorFIN = True

        else:

            # Calculating the ACK value we are looking for.
            ackValue = cPack.TCP_header.seq_num + cPack.payload

        # If ACK value has been previously seen, go to next client packet.
        if ackValue in seenACKValues:
            continue

        # Iterate over each server packet trying to find the matching ACK value.
        for sPack in serverPackets:

            # Checking if we are looking for the establishment/closing packet  ([SYN, ACK] or [FIN, ACK]).
            if packetSYNorFIN:

                # Check if the SYN and ACK bits are set.
                if sPack.TCP_header.flags["ACK"] == 1 and (sPack.TCP_header.flags["SYN"] == 1 or cPack.TCP_header.flags["FIN"] == 1):

                    # Check if ACK Values match.
                    if sPack.TCP_header.ack_num == ackValue:

                        # Add the RTT to stats list.
                        statsRTTValue.append(round((sPack.timestamp - cPack.timestamp), 6))
                        break
                        
            
            # Else, check if the ACK values match, if not go to next packet.
            elif sPack.TCP_header.ack_num == ackValue:

                # Add the RTT to stats list.
                statsRTTValue.append(round((sPack.timestamp - cPack.timestamp), 6))
                break
        
        # Add ackValue to seen ACK values list.
        seenACKValues.append(ackValue)


def basicConnectionDetails(basicInfo, rstTracker, statsTotalRST):
    """
    Prints out the basic connection information to the command line.

    Parameters
    ----------
    basicInfo: list
        Containing Connection Number, Source Address and Port, Destination Address and Port.

    rstTracker: int
        Number of reset connections.

    statsTotalRST: list
        Storing the number of reset connections.
    """
    # Output Basic Connection Details
    print(f'Connection {basicInfo[0]}:')
    print(f'Source Address: {basicInfo[1]}\nDestination Address: {basicInfo[2]}')
    print(f'Source Port: {basicInfo[3]}\nDestination Port: {basicInfo[4]}')
        
    # Checking if Reset bit was set.
    if rstTracker >= 1:

        # Message if rest bit was set.
        print(f'Status: S{basicInfo[5]}F{basicInfo[6]}/R')

        # Store in a reset tracker list.
        statsTotalRST.append(rstTracker)


    else:
            
        # Message if rest bit was not set.
        print(f'Status: S{basicInfo[5]}F{basicInfo[6]}')


def completedConnectionDetails(timeInfo, packetInfo, byteInfo, connectionNumber, totalConnections):
    """
    Prints out the details of a completed connection

    Parameters
    ----------
    timeInfo: list
        Containing the start, end, and duration times.
    
    packetInfo: list
        Containing the bytes sent from Source to Destination, bytes sent from Destination to Source, and Total bytes sent.

    connectionNumber: int
        Which connection this is.

    totalConnection: int
        Overall total number of connections.

    """

    # Output Time information.
    print(f'Start Time: {timeInfo[0]} seconds\nEnd Time: {timeInfo[1]} seconds\nDuration: {timeInfo[2]} seconds')
    print(f'Number of packets sent from Source to Destination: {packetInfo[0]} packets\nNumber of packets sent from Destination to Source: {packetInfo[1]} packets')
    print(f'Total number of packets: {packetInfo[2]} packets')

    # Output Byte information.
    print(f'Number of data bytes sent from Source to Destination: {byteInfo[0]} bytes\nNumber of data bytes sent from Destination to Source: {byteInfo[1]} bytes')
    print(f'Total number of bytes: {byteInfo[2]} bytes')

    # Change the last output line of Connection Details if this is the last connection.
    if connectionNumber == totalConnections:
        print('END')
        print('\n-----------------------------------------------------------------')
        
    else:
        print('END')
        print('+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')


def generalConnectionOutput(completedConnections, statsTotalRST, openConnections):
    """
    Prints out the general details of a completed connection.

    Parameters
    ----------
    completedConnections: int
        Number of completed connections.
    
    statsTotalRST: list
        Containing the number of rst connections.

    openConnections: int
        Number of open connections.
    """    
    
    # Formatting Part C Data and Outputting part C.
    print('\nC) General:')
    print()
    print(f'Total number of complete TCP connections: {completedConnections}')
    print(f'Number of reset TCP connections: {len(statsTotalRST)}')
    print(f'Number of TCP connections that were still open when the trace capture ended: {openConnections}')
    print('\n-----------------------------------------------------------------')


def completeTCPConnectionsOutput(statsTimeDuration, statsNumberOfPackets, statsWindowSize, statsRTTValue):
    """
    Prints the statistics to the command line.

    Parameters
    ----------

    statsTimeDuration: list
        Containing all the timestamp values.

    statsNumberOfPackets: list
        Containing the number of packets sent in both directions.

    statsWindowSize: list
        Containing all the window size values.
    
    statsRTTValue: list
        Containing all the RTT values.
    """

    # Formatting Part D Data and Outputting part D.
    print('\nD) Complete TCP Connections:')

    # Time Duration Stats.
    meanDuration = round(sum(statsTimeDuration) / len(statsTimeDuration), 6)
    print(f'\nMinimum time duration: {min(statsTimeDuration)} seconds')
    print(f'Mean time duration: {meanDuration} seconds')
    print(f'Maximum time duration: {max(statsTimeDuration)} seconds')

    # Round Trip Time (RTT) Stats.
    meanRTT = round((sum(statsRTTValue) / len(statsRTTValue)), 6)
    print(f'\nMinimum RTT value: {min(statsRTTValue)}')
    print(f'Mean RTT value: {meanRTT}')
    print(f'Minimum RTT value: {max(statsRTTValue)}')

    # Packet Stats.
    meanPackets = sum(statsNumberOfPackets) / len(statsNumberOfPackets)
    print(f'\nMinimum number of packets including both send/received: {min(statsNumberOfPackets)} packets')
    print(f'Mean number of packets including both send/received: {meanPackets} packets')
    print(f'Maximum number of packets including both send/received: {max(statsNumberOfPackets)} packets')

    # Window Size Stats.
    meanWindow = round(sum(statsWindowSize) / len(statsWindowSize), 6)
    print(f'\nMinimum receive window size including both send/received: {min(statsWindowSize)} bytes')
    print(f'Mean receive window size including both send/received: {meanWindow} bytes')
    print(f'Maximum receive window size including both send/received: {max(statsWindowSize)} bytes')

    print('\n-----------------------------------------------------------------')

def main():
    
    # Retreving the input file.
    inputFile = sys.argv[1]
    fileChecker = '.cap'

    # Check if the passed file is a .cap.
    if fileChecker not in inputFile:
        print(f'Error: {inputFile} is not of .cap file extension.')
        exit(0)

    # List for storing the bytes read from the passed file.
    rawData = []

    # Read the data byte by byte.
    with open(inputFile, 'rb') as f:
        byte = f.read(1)
        while byte:
            rawData.append(byte)
            byte = f.read(1)
    
    # Creating a list that only contains packet data (Ignoring the global header).
    rawData = rawData[24:]

    # Process packets.
    processedPackets, TCPTuples = processPackets(rawData)

    # Process connections.
    processConnections(processedPackets, TCPTuples)


"""
Credit for the following classes belongs to Kui Wu and his teaching team as they provided most the code for the completion of this assignment.
However, I did modify it slightly as some parts were unnecessary for completion.
"""
class IP_Header:
    src_ip = None 
    dst_ip = None 
    ip_header_len = None 
    total_len = None  
    
    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0  
        
    def set_IP(self,buffer1,buffer2):
        src_addr = struct.unpack('BBBB',buffer1)
        dst_addr = struct.unpack('BBBB',buffer2)
        s_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])
        d_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])
        self.src_ip = s_ip
        self.dst_ip = d_ip
        
    def set_header_len(self,value):
        result = struct.unpack('B', value)[0]
        length = (result & 15)*4
        self.ip_header_len = length

    def set_total_len(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        length = num1+num2+num3+num4
        self.total_len = length
 
class TCP_Header:
    src_port = 0
    dst_port = 0
    seq_num = 0
    ack_num = 0
    data_offset = 0
    flags = {}
    window_size = 0
    
    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.data_offset = 0
        self.flags = {}
        self.window_size = 0
        
    def flags_set_bits(self,ack, rst, syn, fin):
        self.flags["ACK"] = ack
        self.flags["RST"] = rst
        self.flags["SYN"] = syn
        self.flags["FIN"] = fin
        
    def set_src_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.src_port = port
    
    def set_dst_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.dst_port = port
    
    def set_seq_num(self,buffer):
        seq = struct.unpack(">I",buffer)[0]
        self.seq_num = seq
    
    def set_ack_num(self,buffer):
        ack = struct.unpack('>I',buffer)[0]
        self.ack_num = ack
    
    def set_flags(self,buffer):
        value = struct.unpack("B",buffer)[0]
        fin = value & 1
        syn = (value & 2)>>1
        rst = (value & 4)>>2
        ack = (value & 16)>>4
        self.flags_set_bits(ack, rst, syn, fin)

    def set_window_size(self,buffer1, buffer2):
        buffer = buffer2+buffer1
        size = struct.unpack('H',buffer)[0]
        self.window_size = size
        
    def set_data_offset(self,buffer):
        value = struct.unpack("B",buffer)[0]
        length = ((value & 240)>>4)*4
        self.data_offset = length
   

class packet():
    
    IP_header = None
    TCP_header = None
    timestamp = 0
    packetDataLength = 0
    payload = 0
    
    def __init__(self):
        self.IP_header = IP_Header()
        self.TCP_header = TCP_Header()
        self.timestamp = 0
        self.packetDataLength = 0
        
    def timestamp_set(self,buffer1,buffer2,orig_time):
        seconds = struct.unpack('I',buffer1)[0]
        microseconds = struct.unpack('<I',buffer2)[0]
        self.timestamp = round(seconds+microseconds*0.000001-orig_time,6)
        
    def setPayload(self,payloadVal):
        self.payload = payloadVal
    
    def packetDataLengthSet(self, buffer):
        dataPacketLength = struct.unpack('I', buffer)
        self.packetDataLength = int(dataPacketLength[0])


if __name__ == '__main__':
    main()