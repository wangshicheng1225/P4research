# Resubmit_demo 
This is a introduction to our `resubmit_demo` project.
## Overview
We implement a switch which could act as a syn proxy and count the number of packets sent to a specific IP address.
Based on this the switch is able to deal with DDoS attack and other future function extension in security.

## Design
### Modeling
We set up a relatively simple model with h1-s1-h2 topology. We assume that h1 first initializes a session request(send the SYN packet) to h2 and after the three-way handshake, the tcp session is set up and successive packet such as http request will travel between h1 and h2 through switch.
### Workflow
1. H1 initializes a session and send the syn packet. The switch will capture the packet and send back the SYN/ACK packet to h1 without transmiting any message to h2. 
2. When h1 sends the ack packet back, the swtich captures it and sends SYN packet to h2 to establish a session with h2. After the session between h2 is set up, the switch will relay the session A (between h1 and s1) and session B (between s1 and h2).
3. 
## Testing 
We recommend you run `run_demo.sh` to test the code.
This shell will compile the P4 code and run it using bmv2 on mininet, whose topology is specified in `topo.py`.
Next, try starting a simple HTTP server on h1, making a request from h2, then you can  observe that the traffic between the client
and the server are successfully relayed by the proxy. The Seq/Ack
numbers are correctly mapped.

## Source Code
`p4src/syntry.p4`  This is the p4 source code.

`veth_setup.sh`  This script will setup the virtual network interface such as "veth2", "veth4", "veth6" and so on.

`vethsendip.py`  This python script will send specific TCP packet through specific Internet interface. You can modify it for your own needs.  

`topo.py` This script sets up the topology of this model and starts the CLI of p4 switch.

`server.py` This script will runs a simple server on the host.

`sendip.py` Send specific packets through eth0.

`recvip.py` Recieve and handle specifics packets.

`run_demolog.sh` Start the server with log in `ss-log.txt`. Run `veth_setup.sh` firstly.

`run_demo.sh` Start the server on the topology defined in `topo.py` however without log.

`commands.txt` There are table entries here, which will be loaded in the swtich by `topo.py`. You can also add the entry manually through CLI.

`cleanup`clean up the environment such as the virtual network interfaces.

