'''

        CSC 361: Computer Communications and Networks
        Programming Assignment 3: Analysis of IP Protocol
                    Prof: Kui Wu
            Developed By: Austin Bassett

'''
# Modules.
import sys
import struct
import math

# Flag indicating the file was captured on Windows.
WindowCaptured = False

def processPackets(rawData):
    """
    Processes the rawData into PacketObjects which contain the necessary information for each object.

    Parameters
    ----------
    rawData: list
        A list were each entry is one byte.

    Returns
    -------
    processedPacket
        A list of packetObjects.
    """
    
    # Integer Variables.
    headerBytes = 16 
    packetNumber = 1 

    # List Variables.
    processedPacket = []
    sourceNode_UltimateDestination = []

    # Dictionary Variables.
    rttRouters = {}
    protocols = {}
    fragmention = {}

    # Adding flag for finding Ultimate Destination.
    rttRouters['UltimateNeeded'] = 'Yes'
    
    # Variables for tracking the remaining bytes from the pcap file.
    totalBytesLeft = len(rawData)
    timeAdjuster = 0

    # Loop for processing packet headers and packet data.
    while totalBytesLeft > 0:

        # Flag to indicate wheither or not to add the packet.
        addPacket = [True]

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

        # Calculate how many bytes are left in the rawData list.
        totalBytesLeft = totalBytesLeft - headerBytes - dataLength

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
        
        # Process packet data.
        processPacketData(rawPacketData, packetObject, rttRouters, protocols, sourceNode_UltimateDestination, addPacket, fragmention)

        # Add the packet object to the list of packets.
        if addPacket[0] == True:
            processedPacket.append(packetObject)

        # Storing the tuple in a list.
        packetNumber = packetNumber + 1

    # Remove the Ultimate Needed flag.
    rttRouters.pop('UltimateNeeded', None)

    # Return the processed data.
    return processedPacket, rttRouters, protocols, sourceNode_UltimateDestination, fragmention


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


def processPacketData(rawPacketData, packetPointer, rttRouters, protocols, sourceNode_UltimateDestination, addPacket, fragmention):
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
    global WindowCaptured

    # Setting IP length.
    packetPointer.IP_header.set_header_len(rawPacketData[14])

    # Offset variables for adjusting byte locations.
    ethernetOffset = 14
    headerIPOffset = packetPointer.IP_header.ip_header_len + ethernetOffset

    # Creating the Total length byte string.
    totalLen = b''.join([byte for byte in rawPacketData[ (ethernetOffset + 2) : (ethernetOffset + 4)]])

    # Creating the Identification byte string.
    identification = b''.join([byte for byte in rawPacketData[ (ethernetOffset + 4) : (ethernetOffset + 6)]])

    # Creating the Flag/Fragment Offset byte string.
    flags = b''.join([byte for byte in rawPacketData[ (ethernetOffset + 6) : (ethernetOffset + 7)]])
    fragmentOffset = b''.join([byte for byte in rawPacketData[ (ethernetOffset + 6) : (ethernetOffset + 8)]])

    # Creating the Time to Live byt string.
    ttl = b''.join([byte for byte in rawPacketData[ (ethernetOffset + 8 ) : (ethernetOffset + 9) ]])

    # Creating the Protocol byte string.
    protocol = b''.join([byte for byte in rawPacketData[ (ethernetOffset + 9 ) : (ethernetOffset + 10) ]])

    # Creating the Source and Destination byte strings.
    sourceAddress = b''.join([byte for byte in rawPacketData[ (ethernetOffset + 12 ) : (ethernetOffset + 16) ]])
    destinationAddress = b''.join([byte for byte in rawPacketData[ (ethernetOffset + 16) : (ethernetOffset + 20) ]])

    # Setting Flags bits.
    packetPointer.IP_header.set_flags(flags)

    # Setting Fragment offset.
    packetPointer.IP_header.set_fragOffset(fragmentOffset)
    
    # Setting Identification.
    packetPointer.IP_header.set_identification(identification)

    # Setting the Source and Destination values.
    packetPointer.IP_header.set_IP(sourceAddress, destinationAddress)

    # Setting the Total Length.
    packetPointer.IP_header.set_total_len(totalLen)

    # Setting the Time to Live.
    packetPointer.IP_header.set_TimeToLive(ttl)

    # Setting the Protocol.
    packetPointer.IP_header.set_protocol(protocol)

    # If the packet protocol 17 or 1, don't add packetObject to the list.
    if packetPointer.IP_header.protocol != 17 and packetPointer.IP_header.protocol != 1:
        addPacket[0] = False
        return

    # Store the port of a UDP packet
    if packetPointer.IP_header.protocol == 17:

        # Adding the protocol to the dictionary.
        protocols['17'] = 'UDP'

        # Creating Source and Destination Port byte strings.
        sourcePort = b''.join([byte for byte in rawPacketData[headerIPOffset:(headerIPOffset + 2)]])
        destinationPort = b''.join([byte for byte in rawPacketData[(headerIPOffset + 2):(headerIPOffset + 4)]])

        packetPointer.IP_header.set_src_port(sourcePort)
        packetPointer.IP_header.set_dst_port(destinationPort)

        # Getting UDP data, ignoring DNS data.
        packetUDP(packetPointer, rawPacketData,rttRouters, sourceNode_UltimateDestination)
            

    # If this packet is ICMP, get check the ICMP header for type 11.
    if packetPointer.IP_header.protocol == 1:

        # Offset to get the ICMP bits.
        icmpOffset = headerIPOffset + packetPointer.IP_header.ip_header_len + 8

        # Converting the byte string or ICMP type into an integer.
        typeICMPString = b''.join([byte for byte in rawPacketData[headerIPOffset : (headerIPOffset + 1)]])
        typeICMP = struct.unpack('B', typeICMPString)[0]

        # Adding the protocol to the dictionary.
        protocols['1'] = 'ICMP'

        # Extracting ICMP Data.
        packetICMP(packetPointer, icmpOffset, rttRouters, typeICMP, rawPacketData, headerIPOffset, sourceNode_UltimateDestination)

    # Checking if the packet was fragmented.
    if packetPointer.IP_header.flags['MORE'] == 1:

        if packetPointer.IP_header.identification in fragmention:

            # Adding the timestamp of the fragment to the framentation dictionary.
            fragmention[packetPointer.IP_header.identification].append(packetPointer.IP_header.timestamp)

        else:

            # Initializaing a key(identification number) in the fragmentation dictionary with a list containing the packet timestamp.
            fragmention[packetPointer.IP_header.identification] = [packetPointer.IP_header.src_port, packetPointer.timestamp]

    elif packetPointer.IP_header.flags['MORE'] == 0:

        if packetPointer.IP_header.identification in fragmention:

            # Adding the timestamp, source port and fragment offset to the fragmentation dictionary.
            fragmention[packetPointer.IP_header.identification].append(packetPointer.timestamp)
            fragmention[packetPointer.IP_header.identification].append(packetPointer.IP_header.fragOffset)


def packetUDP(packetPointer, rawPacketData,rttRouters, sourceNode_UltimateDestination):

    # Checking if protocol is UDP and not DNS
    if (packetPointer.IP_header.dst_port >= 33434 and packetPointer.IP_header.dst_port <= 33529):

        if rttRouters['UltimateNeeded'] == 'Yes':

            # Changing the 'Yes' flag to the Ultimate Destination Address.
            rttRouters['UltimateNeeded'] = packetPointer.IP_header.dst_ip

            # Getting the Source Node and Ultimate Destination Address.
            ultimateDestinationNode = packetPointer.IP_header.dst_ip

            # Adding the Ultimate Destination to the dictionary.
            rttRouters[ultimateDestinationNode] = []

            # Adding the Source Address and Ultimate Destination to list.
            sourceNode_UltimateDestination.append(packetPointer.IP_header.src_ip)
            sourceNode_UltimateDestination.append(ultimateDestinationNode)


def packetICMP(packetPointer, icmpOffset, rttRouters, typeICMP, rawPacketData, headerIPOffset, sourceNode_UltimateDestination):

        global WindowCaptured

        if typeICMP == 11:

            # Getting the ICMP source IP address
            routerSource = packetPointer.IP_header.src_ip

            if WindowCaptured:

                sequenceNumber = b''.join([byte for byte in rawPacketData[(icmpOffset + 6) : (icmpOffset + 8)]])
                packetPointer.ICMP_Data.set_seq_num(sequenceNumber)

                portValue = [packetPointer.ICMP_Data.ICMP_seqNum, packetPointer.timestamp]

            else:

                # Get the Source and Destination port of the ICMP.
                sourcePort = b''.join([byte for byte in rawPacketData[icmpOffset : (icmpOffset + 2)]])
                destinationPort = b''.join([byte for byte in rawPacketData[(icmpOffset+ 2):(icmpOffset + 4)]])

                packetPointer.ICMP_Data.set_src_port(sourcePort)
                packetPointer.ICMP_Data.set_dst_port(destinationPort)

                # Creating a list of the Source and Destination port and timestamp of the packet.
                portValue = [packetPointer.ICMP_Data.ICMP_srcPort, packetPointer.ICMP_Data.ICMP_dstPort, packetPointer.timestamp]

            # If IP in the dictionary, add the source and destination ports to the list.
            if routerSource in rttRouters:

                rttRouters[routerSource].append(portValue)
            
            else:

                # Add the new IP to the dictionary.
                rttRouters[routerSource] = [portValue]
        
        elif typeICMP == 3:


            # Get the Source and Destination port of the ICMP.
            sourcePort = b''.join([byte for byte in rawPacketData[icmpOffset : (icmpOffset + 2)]])
            destinationPort = b''.join([byte for byte in rawPacketData[(icmpOffset+ 2):(icmpOffset + 4)]])

            packetPointer.ICMP_Data.set_src_port(sourcePort)
            packetPointer.ICMP_Data.set_dst_port(destinationPort)
            
            # Getting the Ultimate Destination Address.
            ultimateDestinationAddress = rttRouters['UltimateNeeded']

            if packetPointer.IP_header.src_ip == ultimateDestinationAddress:
                
                # Creating a list of the Source and Destination port and timestamp of the packet.
                portValue = [packetPointer.ICMP_Data.ICMP_srcPort, packetPointer.ICMP_Data.ICMP_dstPort, packetPointer.timestamp]

                rttRouters[ultimateDestinationAddress].append(portValue)

        # ICMP Type 8 means the file was captured on Windows.
        elif typeICMP == 8:
            
            # Set flag indicating the file was captured on Window.
            if WindowCaptured == False:
                WindowCaptured = True

            sequenceNumber = b''.join([byte for byte in rawPacketData[(headerIPOffset+ 6) : (headerIPOffset + 8)]])
            packetPointer.ICMP_Data.set_seq_num(sequenceNumber)
            
            # Checking if Ultimate Destination is still needed.
            if rttRouters['UltimateNeeded'] == 'Yes':

                # Changing the 'Yes' flag to the Ultimate Destination Address.
                rttRouters['UltimateNeeded'] = packetPointer.IP_header.dst_ip

                # Getting the Source Node and Ultimate Destination Address.
                ultimateDestinationNode = packetPointer.IP_header.dst_ip

                # Adding the Ultimate Destination to the dictionary.
                rttRouters[ultimateDestinationNode] = []

                # Adding the Source Address and Ultimate Destination to list.
                sourceNode_UltimateDestination.append(packetPointer.IP_header.src_ip)
                sourceNode_UltimateDestination.append(ultimateDestinationNode)

        elif typeICMP == 0:
            
            # Getting the Ultimate Destination Address.
            ultimateDestinationAddress = rttRouters['UltimateNeeded']

            sequenceNumber = b''.join([byte for byte in rawPacketData[(headerIPOffset+ 6) : (headerIPOffset + 8)]])
            packetPointer.ICMP_Data.set_seq_num(sequenceNumber)

            packetMatchingInfo = [packetPointer.ICMP_Data.ICMP_seqNum, packetPointer.timestamp]

            rttRouters[ultimateDestinationAddress].append(packetMatchingInfo)


def RTTCalculations(rttRouters, packetData, fragments):

    # List of RTT Results.
    rttResults = []

    # Copying the packetData to speed up the search for matching packet.
    rttPacketData = packetData.copy()

    # Loop over each key of the dictionary.
    for key in rttRouters.keys():
        
        # List for storing the RTT values of each IP.
        rttValues = []

        # Loop over each item of the list located at key.
        for port in rttRouters[key]:

            # If file is Windows, get sequence number.
            if WindowCaptured:

                comparePorts = port[0]
                timestamp = port[1]

            else:

                # Getting the Source Port and Destination Port. (Source Port, Destination Port)
                comparePorts = (port[0], port[1])
                timestamp = port[2]

            # Looping over the packets looking for the matching packet.
            for packet in list(rttPacketData):

                if WindowCaptured:
                    checkPorts = packet.ICMP_Data.ICMP_seqNum

                else:

                    # Creating a tuple for comparing port numbers.
                    checkPorts = (packet.IP_header.src_port, packet.IP_header.dst_port)

                # If not a match, go to next packet.
                if checkPorts != comparePorts:
                    continue
                
                # Calculating the RTT value for this packet, and storing in the list.
                if len(fragments) > 0:
                    
                    # Calculating RTT if fragment packets were present.
                    for fragmentKey in fragments.keys():

                        # Getting the length of the list at this fragmentKey location.
                        fragLength = len(fragments[fragmentKey])
                        
                        if packet.IP_header.src_port != fragments[fragmentKey][0]:
                            continue
                                
                        # Appending the RTT of each fragment.
                        for index in range(1, fragLength-1):
                            rttValues.append(timestamp - fragments[fragmentKey][index])

                else:

                    rttValues.append(timestamp - packet.timestamp)

                # Getting the TTL of the packet.
                packetTTL = packet.IP_header.timeToLive
                
                # Remove this packet speeding up the search for the other keys.
                rttPacketData.remove(packet)

                break
        
        # Fail safe for preventing division by zero.
        if len(rttValues) == 0:

            total = 1

        else:

            total = len(rttValues)
        
        # Calculating the Average RTT time for this key to the source address.
        averageRTT = sum(rttValues) / total
        mu = averageRTT
        averageRTT = round((averageRTT * 1000), 6)

        # Calculating Standard Derivation.
        derivations = [(x - mu) ** 2 for x in rttValues]
        standardDerivation = math.sqrt(sum(derivations) / total)
        standardDerivation = round((standardDerivation * 1000), 6)

        # Replacing the list located at key with average RTT.
        rttResults.append([packetTTL, key, averageRTT, standardDerivation])

    # Sorting the results based on their TTL.
    rttResults.sort(key=lambda x: x[0])

    return rttResults


def outputResults(rttResults, sourceDestinationAddress, protocols, fragments):
    
    # Output the Source and Ultimate Destination Address.
    print(f'\nThe IP address of the source node: {sourceDestinationAddress[0]}')
    print(f'The IP address of ultimate destination node: {sourceDestinationAddress[1]}')

    # Output the Intermediate Routers.
    print('The IP addresses of the intermediate destination nodes:')
    intermediateRouterNumber = 1
    for item in rttResults:

        # Skipping the Ultimate Destination.
        if item[1] == sourceDestinationAddress[1]:
            continue

        print(f'\trouter {intermediateRouterNumber}: {item[1]}')
        intermediateRouterNumber += 1

    # Output the protocol values.
    print('\nThe values in the protocol field of IP headers:')
    for key in protocols.keys():
        print(f'\t{key}: {protocols[key]}')

    print()

    # Output the number of fragments created and the offset of the last fragment.
    if len(fragments) == 0:

        print(f'The number of fragments created from the original datagram is: {0}')
        print(f'The offset of the last fragment is: {0}')

    else:
        for key in fragments.keys():

            # Getting the number of fragments. 
            totalFragments = len(fragments[key]) 

            print(f'The number of fragments created from the original datagram {key} is: {totalFragments - 2}')
            print(f'The offset of the last fragment is: {fragments[key][totalFragments - 1]}')
            print()


    print()

    # Output the average RTT Times.
    for item in rttResults:
    
        print(f'The avg RTT between {sourceDestinationAddress[0]} and {item[1]} is: {item[2]} ms, the s.d. is: {item[3]} ms')

    print()



def main():
    
    # Retreving the input file.
    inputFile = sys.argv[1]
    fileChecker = '.pcap'

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
    processedPackets, rttRouters, protocols, sourceDestinationAddress, fragments = processPackets(rawData)

    # RTT Calculations.
    rttResults = RTTCalculations(rttRouters, processedPackets, fragments)
    
    # Output the information to the command line.
    outputResults(rttResults, sourceDestinationAddress, protocols, fragments)
        
    
"""
Credit for the following classes belongs to Kui Wu and his teaching team as they provided most the code for the completion of this assignment.
However, I did modify it slightly as some parts were unnecessary for completion.
"""
class IP_Header:

    src_ip = None
    src_port = None
    dst_ip = None
    dst_port = None 
    ip_header_len = None 
    timeToLive = None
    total_len = None
    protocol = None  
    identification = None
    fragOffset = None
    flags = {}
    
    def __init__(self):
        self.src_ip = None
        self.src_port = None
        self.dst_ip = None
        self.dst_port = None
        self.identification = None
        self.fragOffset = None
        self.timeToLive = None
        self.ip_header_len = 0
        self.total_len = 0  
        self.protocol = 0
        self.flags = {}
        
    def flag_bits(self, more, dont):
        self.flags['DONT'] = dont
        self.flags['MORE'] = more

    def set_IP(self,buffer1,buffer2):
        src_addr = struct.unpack('BBBB',buffer1)
        dst_addr = struct.unpack('BBBB',buffer2)
        s_ip = str(src_addr[0]) + '.' + str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])
        d_ip = str(dst_addr[0]) + '.' + str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])
        self.src_ip = s_ip
        self.dst_ip = d_ip
        
    def set_header_len(self,value):
        result = struct.unpack('B', value)[0]
        length = (result & 15)*4
        self.ip_header_len = length

    def set_src_port(self,buffer):
        buffer = struct.unpack('BB', buffer)
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.src_port = port
    
    def set_dst_port(self,buffer):
        buffer = struct.unpack('BB', buffer)
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.dst_port = port

    def set_total_len(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        length = num1+num2+num3+num4
        self.total_len = length

    def set_flags(self, buffer):
        value = struct.unpack("B",buffer)[0]
        more_bit = (value & 32) >> 5
        dont_bit = (value & 64) >> 6
        self.flag_bits(more_bit, dont_bit)

    def set_fragOffset(self, buffer):
        value = struct.unpack('>H', buffer)[0]
        offset = (value & 8191) * 8
        self.fragOffset = offset

    def set_protocol(self, buffer):
        protocolValue = struct.unpack('B', buffer)[0]
        self.protocol = int(protocolValue)

    def set_TimeToLive(self, buffer):
        ttl = struct.unpack('B', buffer)[0]
        self.timeToLive = int(ttl)

    def set_identification(self, buffer):
        buffer = struct.unpack('>H', buffer)[0]
        self.identification = buffer

class ICMP:

    ICMP_srcPort = None
    ICMP_dstPort = None
    ICMP_seqNum = None

    def __init__(self):
        self.ICMP_srcPort = None
        self.ICMP_dstPort = None
        self.ICMP_seqNum = None
    
    def set_src_port(self,buffer):
        buffer = struct.unpack('BB', buffer)
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.ICMP_srcPort = port
    
    def set_dst_port(self,buffer):
        buffer  = struct.unpack('BB', buffer)
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.ICMP_dstPort = port

    def set_seq_num(self, buffer):
        sequenceNumber = struct.unpack('H', buffer)[0]
        self.ICMP_seqNum = sequenceNumber
 

class packet():
    
    IP_header = None
    ICMP_Data = None
    timestamp = 0
    packetDataLength = 0
    payload = 0
    
    def __init__(self):
        self.IP_header = IP_Header()
        self.ICMP_Data = ICMP()
        self.timestamp = 0
        self.packetDataLength = 0
        
    def timestamp_set(self,buffer1,buffer2,orig_time):
        seconds = struct.unpack('I',buffer1)[0]
        microseconds = struct.unpack('<I',buffer2)[0]
        self.timestamp = round(seconds+microseconds*0.000000001-orig_time,6)
        
    def setPayload(self,payloadVal):
        self.payload = payloadVal
    
    def packetDataLengthSet(self, buffer):
        dataPacketLength = struct.unpack('I', buffer)
        self.packetDataLength = int(dataPacketLength[0])


if __name__ == '__main__':
    main()