# P4research
This is a repository for p4 research
## source routing
	This is a simple demo model for p4 development framework test, which is based on simple_nat in /examples/simple_nat and demo1 in p4guide repo.
	The topo is similar to simple_nat.
	The p4 source comes from demo1.
	The table entries is based on the topo with the help of demo1
	sengip.py and recvip.py will run on h1 and h2.
	Maybe I should disable ipv6 like what source_routing and simple_nat dofor unknown ipv6 packets.
	ichou desu
## SYNtry
	This is a simple demo for syn proxy
	We use Register to store the store of every session whose index is marked by the hash of 4-touple
	When SYN init a session, the Register of is_SYN will be 1 while Registerof is_ACK keeps 0. It will sent this packet to h2 rather than return to h1 fo lower difficulty. At this time, the SYN with same hash will be droopped.
	Similarly, when ACK of this session (<=> with same hash) comes in, the Register of is_ACK will be 1 and this packet is sent to h2. And any syn or ack with same hash will be dropped.
