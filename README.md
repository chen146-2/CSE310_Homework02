# Programming Assignment 02

    Name: Kevin Chen
    Student ID: 113448049
    NET-ID: Chen146-2

## In this README, there are two sections:

(i) High-Level Summary
    --> the high-level summary of the analysis_pcap_tcp.py code
    --> includes how I estimated the answers to the questions in Part A and Part B

(ii) Instructions
    --> the instructions on how to run my code

## High-Level Summary:

My program utilizes the python pcap library, dpkt, to analyze the information from the assignment2.pcap file. I imported the os module to easily allow users of the program to easily open the assignment2.pcap within the same directory that analysis_pcap_tcp.py is located.

The first few lines of code, from 7 to 10, are where I open the pcap file for reading and parsing through. I used two for overall for loops to generate the desired values from Parts A and B, which have a runtime complexity of around O(2n), where n is the number of packets in the pcap file.

The next few lines of code, 11-18, are where I initialize certain values and structures that will be essential for storing information and data values later on. As mentioned from the homework document, I hard coded the sender and receiver IP addresses since the document allowed for it. I had also initialized a variable, receiver_port, with the int 80 for ease of use in later scenarios.

My first for-loop, which spans from lines 19 to 43, is where I store the time stamps for when a flow is started from sender port x to receiver port 80 (FLAG: [ SYN ]), along with when a flow is finalized (Flag: [FIN, ACK]). These values will be used to calculate the 'period' value, which is used in the calculation of the throughput for each flow. With this for-loop, I do a lot of initializing structures with values, such as the time stamp values needed for calculating the congestion window values for each flow (as observed with the variable congestion, which is a dictionary).

My second for-loop is used for calculating the throughput values for each flow, along with calculating the first three congestion window sizes for each flow in the pcap file. This for-loop manipulates some dictionaries I have created, flow{}, which is used to store certain values, such as receive window sizes, seq and ack numbers for the first two transactions, and more. Another dictionary, congestion {}, contributes to the calculation for each congestion window sizes by making sure that the current time stamps are within the range of time from timestamp of the first valid packet to the sum of the timestamp of the first valid packet plus the RTT, which is retrieved from the first two indices of the congestion dictionary's stored array. A count variable allows me to better visualize where certain packets are experiencing certain traits.

I calculate the throughput values at lines 82-89, where I create a new array by first initializing it with the period time values (line 84). The units of the period values are in seconds. Next, I use the total data of packets stored in the flow dictionary to compute the actual throughput by dividing the total amount of data from each flow by the period from when the flag=[ PSH, ACK] to flag=[ FIN, ACK]. The units for throughput are packets per second. 

From lines 91 to 134, I am just formatting the desired values into a nice and organized way for a "pretty" output. The first outputted component includes the assignment number, the part it describes, and my net-id. I also included the TCP Flow indices, the source IP addresses, the destination IP addresses, the source ports, the destination ports, and the throughputs for each flow that was present in the pcap file. The expected output for the first component should be the same as what is displayed below:

    ----------------------------------------------------------------------------------------------------
    |                                                                                                  |
    |                           PROGRAMMING ASSIGNMENT 02 - PART A - CHEN146                           |
    |                                                                                                  |
    ----------------------------------------------------------------------------------------------------
    | TCP FLOW | SOURCE IP ADDR. | DESTINATION IP ADDR. | SRC PORT | DEST. PORT |      THROUGHPUT      |
    ----------------------------------------------------------------------------------------------------
    |    1     | 130.245.145.12  |     128.208.2.198    |  43498   |     80     |  5133392.7200229885  |
    |    2     | 130.245.145.12  |     128.208.2.198    |  43500   |     80     |  1256529.9264600703  |
    |    3     | 130.245.145.12  |     128.208.2.198    |  43502   |     80     |  1447924.7773412564  |
    ----------------------------------------------------------------------------------------------------

For the throughput calculation, the process that I went about performing was by adding up the size of each packet of data (len(tcp)) only if the size of the data was greater than 0, which would only account for requests that aren't empty, so we wouldn't be adding the size of the headers and other components of the TCP request into our overall total sum of data. Then, for each flow, I divided the total amount of data, which was just mentioned, by the period of each flow. For the period of each flow, I calculated this value for each flow by finding the timestamp of the flag of [ SYN ], which indicates that connection is established with the port 80, and the timestamp of the flag of [FIN, ACK]. After this, I find the absolute value of their difference, and divide the total amount of data for each flow with their respective period. By doing this, we get the throughput, which is measured in packets per second. 

The next three components that are printed to output are the next two transactions after connection setup for each flow. I placed each respective transaction in a well designed table with easy to read tuples (SEQ Num, ACK Num) for each request/response. I also displayed the receive window size for each respective request/response from the sender to receiver, and vice versa. The output that you should see when you run the program is displayed below:

                FIRST TWO TRANSACTIONS AFTER CONNECTION SETUP FOR FLOW 1
    ------------------------------------------------------------------------------------------
    |          SOURCE  ==>  DESTINATION         |   (SEQ NUMBER, ACK NUMBER)  | WINDOW SIZE  |
    ------------------------------------------------------------------------------------------
    | 130.245.145.12:43498 ==> 128.208.2.198:80 | ( 705669103 , 1921750144 ) |      3       |
    | 128.208.2.198:80 ==> 130.245.145.12:43498 | ( 1921750144 , 705669127 ) |      3       |
    ------------------------------------------------------------------------------------------
    | 130.245.145.12:43498 ==> 128.208.2.198:80 | ( 705669127 , 1921750144 ) |      3       |
    | 128.208.2.198:80 ==> 130.245.145.12:43498 | ( 1921750144 , 705670575 ) |      3       |
    ------------------------------------------------------------------------------------------

    

                FIRST TWO TRANSACTIONS AFTER CONNECTION SETUP FOR FLOW 2
    ------------------------------------------------------------------------------------------
    |          SOURCE  ==>  DESTINATION         |   (SEQ NUMBER, ACK NUMBER)  | WINDOW SIZE  |
    ------------------------------------------------------------------------------------------
    | 130.245.145.12:43500 ==> 128.208.2.198:80 | ( 3636173852 , 2335809728 ) |      3       |
    | 128.208.2.198:80 ==> 130.245.145.12:43500 | ( 2335809728 , 3636173876 ) |      3       |
    ------------------------------------------------------------------------------------------
    | 130.245.145.12:43500 ==> 128.208.2.198:80 | ( 3636173876 , 2335809728 ) |      3       |
    | 128.208.2.198:80 ==> 130.245.145.12:43500 | ( 2335809728 , 3636175324 ) |      3       |
    ------------------------------------------------------------------------------------------

    

                FIRST TWO TRANSACTIONS AFTER CONNECTION SETUP FOR FLOW 3
    ------------------------------------------------------------------------------------------
    |          SOURCE  ==>  DESTINATION         |   (SEQ NUMBER, ACK NUMBER)  | WINDOW SIZE  |
    ------------------------------------------------------------------------------------------
    | 130.245.145.12:43502 ==> 128.208.2.198:80 | ( 2558634630 , 3429921723 ) |      3       |
    | 128.208.2.198:80 ==> 130.245.145.12:43502 | ( 3429921723 , 2558634654 ) |      3       |
    ------------------------------------------------------------------------------------------
    | 130.245.145.12:43502 ==> 128.208.2.198:80 | ( 2558634654 , 3429921723 ) |      3       |
    | 128.208.2.198:80 ==> 130.245.145.12:43502 | ( 3429921723 , 2558636102 ) |      3       |
    ------------------------------------------------------------------------------------------

From what was just printed, that was the Part A and the expected values that the assignment document wanted to see. Now we will move onto Part B, which the code for calculating the congestion window sizes for each flow and the retransmissions due to the timeout and/or triple duplicate ACK could be found from the earlier mentioned lines of code, which includes the two large for-loops and the many boolean conditionals. Additionally, you will find the code for how I decided on the retransmissions from lines 162 to 171, which decide whether an ACK is a duplicate or not based on the ACK number the response has from port 80 to the respective port x, where x is in [43498, 43500, 43502]. If there was more than one response, it must've been retransmitted due to timeout, whereas the triple dup ack retransmission can be decided from the frequency of the duplicate responses with the same ACK nums. The output that you would get from running the program is:

    ----------------------------------------------------------------------------------------------------
    |                                                                                                  |
    |                           PROGRAMMING ASSIGNMENT 02 - PART B - CHEN146                           |
    |                                                                                                  |
    ----------------------------------------------------------------------------------------------------

    ----------------------------------------------------------------------------------------------------
    |                                   CONGESTION WINDOWS                                             |
    ----------------------------------------------------------------------------------------------------
    |       PORT       |         CWND 01         |         CWND 02         |          CWND 03          |
    ----------------------------------------------------------------------------------------------------
    |       43498      |           10            |          19             |             34            |
    ----------------------------------------------------------------------------------------------------
    |       43500      |           10            |          31             |             46            |
    ----------------------------------------------------------------------------------------------------
    |       43502      |           10            |          21             |             34            |
    ----------------------------------------------------------------------------------------------------

    ----------------------------------------------------------------------------------------------------
    |                                       RETRANSMISSIONS                                            |
    ----------------------------------------------------------------------------------------------------
    |       PORT       |         DUE TO TIMEOUT          |          DUE TO TRIPLE DUPLICATE ACKS       |
    ----------------------------------------------------------------------------------------------------
    |       43498      |               3                 |                 2                           |
    ----------------------------------------------------------------------------------------------------
    |       43500      |               81                |                  3                          |
    ----------------------------------------------------------------------------------------------------
    |       43502      |               0                 |                 0                           |
    ----------------------------------------------------------------------------------------------------

The way that I estimated the congestion window sizes for Part B is by first calculating the RTT for each flow by finding the difference between the timestamp where we encounter a [FIN, ACK] flag, where tcp.flags==17, and a [PSH, ACK] flag. By calculating this difference, it gives us the RTT we desire. Then, I iterate through the pcap file and for the first valid packet sent from the sender ([43498, 43500, 43502]) to receiver (port 80), I would set the starting timestamp to that timestamp and keep iterating count for each respective port's congestion windows till the current timestamp is less than or equal to (<=) the starting timestamp plus the RTT. This will produce the number of packets sent from sender to receiver within a given RTT. 

## Instructions:

This part is where I will be giving you instructions on how to run my program. When you retrieve my zip folder, there will be three files, the first one is the main python program that you will be running, which is named **analysis_pcap_tcp.py**. A second file that you will find in the zip folder **assignment2.pcap**, which will be used within the program for testing and outputting the results. A third file is named **README.md**, which contains information such as a high-level summary and the instructions to take to successfully run the program I created.

This is one approach to running the program:
    
    (1) First, open an IDE. I would recommend the use of the platform called Visual Studio Code, which is free and easy to use.

    (2) When you are in Visual Studio Code, open up the folder where all three files are located.

    (3) Double click on the file labeled 'analysis_pcap_tcp.py'

    (4) You can right click within the python program to open up the possible operations to the current program file

    (5) Click on 'Run Python File in Terminal'

    (6) You should be able to have the desired output and stats presented to you in the terminal/console.

This is another approach to running my program:

    (1) Open up Visual Studio Code

    (2) Open up the folder where all three files are located

    (3) Open up the terminal within the folder in VS Code using the possible shortcuts:
        --> Ctrl + ` 
        --> Ctrl + Shift + `
        --> View > Terminal (From menu commands)
        --> Terminal > New Terminal (From menu commands)

    (4) Type into terminal the following:

        **python analysis_pcap_tcp.py**

    (5) You should be able to have the desired output and stats presented to you in the terminal/console.
