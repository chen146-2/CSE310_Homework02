import dpkt, struct


f = open('/Users/kevin/Downloads/assignment2.pcap','rb')
pcap = dpkt.pcap.Reader(f)
count = 0
flow = {}
sender='130.245.145.12'
receiver='128.208.2.198'
receiver_port = 80
for ts, buf in pcap:
    # if count == 5:
    #     break
    # else:
    #     print('======= count: ' + str(count) + ' =======')
    #     eth = dpkt.ethernet.Ethernet(buf)
    #     #print('eth: ', eth)
    #     ip = eth.data
    #     #print('ip: ', ip.src)
    #     tcp = ip.data
    #     print('tcp.sport: '+str(tcp.sport)+ ' , tcp,dport: ' +str(tcp.dport))
    #     print('tcp.seq: ' +str(tcp.seq) + ' , tcp.ack: ' + str(tcp.ack))
    #     count +=1
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data
    #tcp.flags == 17 is for [FIN, ACK]
    if tcp.flags==2:
        print('count: ' + str(count+1))
        print('source port: ' + str(tcp.sport))
        print('destination port: ' + str(tcp.dport))
        print('sequence #: ' + str(tcp.seq))
        print('acknowledgement #: ' + str(tcp.ack))
        print('flag: ' + str(tcp.flags))
        print('syn\n')
        flow[tcp.sport] = {}
    elif tcp.flags==16 and tcp.sport != receiver_port:
        if (len(flow[tcp.sport])==0):
            flow[tcp.sport]['win']=tcp.win
            flow[tcp.sport]['throughput']=0
            flow[tcp.sport][tcp.seq]=tcp.ack
        elif(len(flow[tcp.sport])<5):    
            flow[tcp.sport][tcp.seq]=tcp.ack
            flow[tcp.sport]['throughput']+=len(tcp)
        else:
            flow[tcp.sport]['throughput'] += len(tcp)
    #elif tcp.flags==24 and tcp.sport != receiver_port:
    #    flow[tcp.sport]['throughput'] += len(tcp.data)
    count+=1

# this part is to print out the flows (source ip addresses, destination ip addresses, source port numbers, destination port numbers, and throughputs)

print('''
    ------------------------------------------------------------------------------------------
    | TCP FLOW | SOURCE IP ADDR. | DESTINATION IP ADDR. | SRC PORT | DEST. PORT | THROUGHPUT |
    ------------------------------------------------------------------------------------------''')
index = 1
for value in flow:
    print('    |    {ind}     | {source_ip}  |     {dest_ip}    |  {src_port}   |     {dest_port}     | {throughput} |'.format(ind=index, 
        source_ip=sender, dest_ip=receiver, src_port=value, dest_port=receiver_port, throughput=0))
    index+=1
print('    ------------------------------------------------------------------------------------------\n')

# this part is to print out each flow and the first two transactions after the TCP connection is set up (from sender to receiver)
# this includes the values of the sequence number, acknowledgement numbers, and window sizes
index=1
for value in flow:
    keyList = list(flow[value].keys())
    window = flow[value][keyList[0]]
    seqNum01 = keyList[2]
    ackNum01 = flow[value][seqNum01]
    seqNum02 = keyList[3]
    ackNum02 = flow[value][seqNum02]
    ackNum03 = keyList[4]
    print(f'''
                FIRST TWO TRANSACTIONS AFTER CONNECTION SETUP FOR FLOW {index}
    ------------------------------------------------------------------------------------------
    |          SOURCE  ==>  DESTINATION         |   (SEQ NUMBER, ACK NUMBER)  | WINDOW SIZE |
    ------------------------------------------------------------------------------------------
    | {sender}:{value} ==> {receiver}:{receiver_port} | ( {seqNum01} , {ackNum01} ) |      {window}      |
    | {receiver}:{receiver_port} ==> {sender}:{value} | ( {ackNum01} , {seqNum02} ) |      {window}      |
    ------------------------------------------------------------------------------------------
    | {sender}:{value} ==> {receiver}:{receiver_port} | ( {seqNum02} , {ackNum02} ) |      {window}      |
    | {receiver}:{receiver_port} ==> {sender}:{value} | ( {ackNum02} , {ackNum03} ) |      {window}      |
    ------------------------------------------------------------------------------------------\n
    ''')
    index+=1

print('--- throughput ---')
for value in flow:
    print(str(value) + ' ==> ' + str(flow[value]['throughput']))
f.close()