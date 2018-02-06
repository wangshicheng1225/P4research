# P4research
This is a repository for our p4 research
## Introduction
There are 3 directories in our repository as follow.
### SYNtry 
This is a simple demo for syn proxy
We use Register to store the store of every session whose index is marked by the hash of 4-touple.
When SYN init a session, the Register of is_SYN will be 1 while Registerof is_ACK keeps 0. It will sent this packet to h2 rather than return to h1 fo lower difficulty. At this time, the SYN with same hash will be droopped.
Similarly, when ACK of this session (if and only if the packet has same hash) comes in, the Register of is_ACK will be 1 and this packet is sent to h2. And any syn or ack with same hash will be dropped.
### ping_switch
This is a simple L2 switch for an h1-s1-h2 topology which. We implement it in a somewhat tricky way that we just transmit the packet from port 1 to port 2 and vice versa. We provide the code block for parsing IP header and TCP header for future
function extension on higher layer such as TCP flowlet switching.
### resubmit_demo
This is our most important work aiming at enhancing network security using programmable data plane. So we will introduce it in more detail in `README_resubmit_demo.md`

## Environment
We build our experimental environment according the P4's repository in github. 
Please follow the instructions here to make sure that your environment is setup correctly.
[https://github.com/p4lang/tutorials](https://github.com/p4lang/tutorials)
And please remember to edit 
`env.sh` to point to your local copy of `bmv2` and `p4c-bm`.
We highly recommend that you setup your environment according to the `tutorials` and clone our repository in the same directory with `SIGCOMM_2015` in `tutorials`.

