/* -*- mode: P4_14 -*- */

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}
header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}
header ethernet_t ethernet;
header ipv4_t ipv4;



parser start {

	set_metadata(meta.in_port, standard_metadata.ingress_port);

    return parse_ethernet;
}

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP  0x0806
parser parse_ethernet {
    extract(ethernet);
	
	set_metadata(meta.macSrcAddr, ethernet.srcAddr);
	set_metadata(meta.macDstAddr, ethernet.dstAddr);
	
	return ingress;
//	return select(latest.etherType) {
//      ETHERTYPE_IPV4 : parse_ipv4;
//		ETHERTYPE_ARP  : parse_arp;
//        default: ingress;
//    }
}

header_type meta_t{
	fields {
		in_port:8;
		macSrcAddr:48;
		macDstAddr:48;

	}

}

metadata meta_t meta;

action _drop() {
    drop();
}


action L2_forward(e_port)
{
	modify_field(standard_metadata.egress_spec,e_port); 
}

table L2_switch_table
{
	reads {
		meta.in_port:exact;
	
	}
	actions {
		_drop;
		L2_forward;
	}
}
/*
action arp_forward(dstMac, i_port)
{
}

action ipv4_forward(dstMac, e_port)
{
	modify_field(ethernet.srcAddr, ethernet.dstAddr);
	modify_field(ethernet.dstAddr, dstMac);
	modify_field(standard_metadata.egress_spec, e_port);
//	add_to_field(ipv4.ttl, -1);
	
}

// TODO table ttl_check

table ipv4_lpm_table
{
	reads {
		//ipv4.dstAddr : lpm;
		ethernet.dstAddr: lpm;
	}
	actions {
		_drop;
		ipv4_forward;
	}
}*/

control ingress {
	//apply(ipv4_lpm_table);
	apply(L2_switch_table);


}
control egress{

}


