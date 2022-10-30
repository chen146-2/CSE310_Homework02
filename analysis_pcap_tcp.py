import dpkt


f = open('/Users/kevin/Downloads/assignment2.pcap','rb')
pcap = dpkt.pcap.Reader(f)
f2 = open('/Users/kevin/Downloads/assignment2.pcap','rb')
pcap2 = dpkt.pcap.Reader(f2)
count = 0
flow = {}
times={}
sender='130.245.145.12'
receiver='128.208.2.198'
receiver_port = 80
for ts, buf in pcap2:
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data
    if tcp.flags==2:
        times[tcp.sport]= []
        times[tcp.sport].append(ts)
    elif tcp.flags==17 and tcp.sport == receiver_port:
        times[tcp.dport].append(ts)
f2.close()
for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data

    if tcp.flags==2:
        flow[tcp.sport] = {}
        #times[tcp.sport] = []
        #times[tcp.sport].append(ts)
        flow[tcp.sport]['throughput']=0
    elif tcp.flags==16 and tcp.sport != receiver_port:
        if (len(flow[tcp.sport])==1):
            flow[tcp.sport]['win']=tcp.win
            flow[tcp.sport][tcp.seq]=tcp.ack
        elif(len(flow[tcp.sport])<5):    
            flow[tcp.sport][tcp.seq]=tcp.ack
            if len(tcp.data)>0:
                flow[tcp.sport]['throughput'] +=len(tcp)
        elif ts < times[tcp.sport][1] and len(tcp.data)>0:
            flow[tcp.sport]['throughput'] += len(tcp)
    elif tcp.flags !=16 and tcp.sport!= receiver_port:
        if ts < times[tcp.sport][1] and len(tcp.data)>0:
            flow[tcp.sport]['throughput']+=len(tcp)
    count+=1

# this part is to calculate the throughputs for each flow

throughputs=[]
print('----------- times -------------')
for value in times:
    print(times[value][1]-times[value][0])
    throughputs.append(times[value][1]-times[value][0])
count=0
print('-------- throughput -----------')
for value in flow:
    print(flow[value]['throughput'])
    throughputs[count]=(flow[value]['throughput']/throughputs[count])
    count+=1

# this part is to print out the flows (source ip addresses, destination ip addresses, source port numbers, destination port numbers, and throughputs)

print('''
    ----------------------------------------------------------------------------------------------------
    | TCP FLOW | SOURCE IP ADDR. | DESTINATION IP ADDR. | SRC PORT | DEST. PORT |      THROUGHPUT      |
    ----------------------------------------------------------------------------------------------------''')

index = 1

for value in flow:
    print('    |    {ind}     | {source_ip}  |     {dest_ip}    |  {src_port}   |     {dest_port}     |  {throughput}  |'.format(ind=index, 
        source_ip=sender, dest_ip=receiver, src_port=value, dest_port=receiver_port, throughput=throughputs[index-1]))
    index+=1
print('    ----------------------------------------------------------------------------------------------------\n')

# this part is to print out each flow and the first two transactions after the TCP connection is set up (from sender to receiver)
# this includes the values of the sequence number, acknowledgement numbers, and window sizes
index=1

for value in flow:
    keyList = list(flow[value].keys())
    window = flow[value][keyList[1]]
    seqNum01 = keyList[2]
    ackNum01 = flow[value][seqNum01]
    seqNum02 = keyList[3]
    ackNum02 = flow[value][seqNum02]
    ackNum03 = keyList[4]
    print(f'''
                FIRST TWO TRANSACTIONS AFTER CONNECTION SETUP FOR FLOW {index}
    ------------------------------------------------------------------------------------------
    |          SOURCE  ==>  DESTINATION         |   (SEQ NUMBER, ACK NUMBER)  | WINDOW SIZE  |
    ------------------------------------------------------------------------------------------
    | {sender}:{value} ==> {receiver}:{receiver_port} | ( {seqNum01} , {ackNum01} ) |      {window}       |
    | {receiver}:{receiver_port} ==> {sender}:{value} | ( {ackNum01} , {seqNum02} ) |      {window}       |
    ------------------------------------------------------------------------------------------
    | {sender}:{value} ==> {receiver}:{receiver_port} | ( {seqNum02} , {ackNum02} ) |      {window}       |
    | {receiver}:{receiver_port} ==> {sender}:{value} | ( {ackNum02} , {ackNum03} ) |      {window}       |
    ------------------------------------------------------------------------------------------\n
    ''')
    index+=1

f.close()