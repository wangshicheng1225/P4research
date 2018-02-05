# Resubmit_demo 
This is a introduction to our `resubmit_demo` project.
## Overview
We implement a switch which could act as a syn proxy and count the number of packets sent to a specific IP address.
Based on this the switch is able to deal with DDoS attack and other future function extension in security.

## Design
###Modeling
We set up a relatively simple model with h1-s1-h2 topology. We assume that h1 first initializes a session request(send the SYN packet) to h2 and after the three-way handshake, the tcp session is set up and successive packet such as http request will travel between h1 and h2 through switch.
###Workflow
1. H1 initializes a session and send the syn packet. The switch will capture the packet and send back the SYN/ACK packet to h1 without transmiting any message to h2. 
2. When h1 sends the ack packet back, the swtich captures it and sends SYN packet to h2 to establish a session with h2. After the session between h2 is set up, the switch will relay the session A (between h1 and s1) and session B (between s1 and h2).

## Key Issues

* **Attack Defend:** 
When h1 send its first SYN to h2(actually s1) and this packet gets captured, it cannot send another SYN or others except ACK to establish the session with the switch(s1). Any invalid packet sent into s1 in this state will be dropped by the switch. We introduce this feature to defend the underlying SYN flood attack and others malicious attck. Similarly, After the switch sends its SYN to h2 to initialize the session, any packet from h2 excpet the expected SYN/ACK with correct sequence number will be all dropped.
* **Transparency for endpoint:** 
Only the ACK packet of h1 arrives at s1, will the switch send SYN to h2 to establish session with h2. The problem lies on the point that if the successive packet arrives before the session with h2 is set up, this packet may not be transmited successfully. We apply the characteristic "resubmit" of P4 to solve it. Before the session with h2 get set up, the packet from h1 will keep in "resubmit". It will not be transmited until the session is established when the switch captures the SYN/ACK packet from h2. 
* **Relay the Connection:**
Maybe you have find a latent problem in the above. It is the switch that reply h1 with SYN/ACK within sequence number in it rather than h2. But the switch cannot know the real sequence number h2 wants to send. So it will be important to transfer the sequence number between two sessions.

##Coding
1. When packets comes in and the parsing process finished, the index in the registers array of this packet will be obtained. After that we can get the state information about this session, and corresponding "operand"(i.e. `reply_type` in the code) will be assigned to a certain field in `metadata`, with expected operations performed finally.
1. We use register arrays for state storage of every session. We take the hash of 5-tuple as the index of arrays. But the 5-tuple hash values of h1-s1 session and s1-h2 session are different even they are actually supposed to share the same one. So we use two hash algorithms to handle this. Packets from h1 apply algorithm 1 and Packets from h2 apply the second so that they get the same hash as well as the index. To get more details please see the our code. And to learn more about why h1-s1 session and s1-h1 session get different hash values, please read, compile and run our `crc16test.p4` in `p4src/`.   

##Testing 
We recommend you run `run_demo.sh` to test the code.
This shell will compile the P4 code and run it using bmv2 on mininet, whose topology is specified in `topo.py`.
Next, try starting a simple HTTP server on h1, making a request from h2, then you can  observe that the trafc between the client
and the server are successfully relayed by the proxy. The Seq/Ack
numbers are correctly mapped.

