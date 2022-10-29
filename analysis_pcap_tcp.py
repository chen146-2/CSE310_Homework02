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
            flow[tcp.sport][tcp.seq]=tcp.ack
            print(flow)
        elif(len(flow[tcp.sport])<3):    
            flow[tcp.sport][tcp.seq]=tcp.ack
            print(flow)
    count+=1
print('overall flow:\n' + str(flow))
f.close()