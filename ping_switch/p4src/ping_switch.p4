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
	
	return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
	//	ETHERTYPE_ARP  : parse_arp;
        default: ingress;
    }
}

header ipv4_t ipv4;

field_list ipv4_checksum_list {
	ipv4.version;	
	ipv4.ihl;
	ipv4.diffserv;
	ipv4.totalLen;
	ipv4.identification;
	ipv4.flags;
	ipv4.fragOffset;
	ipv4.ttl;
	ipv4.protocol;
	ipv4.srcAddr;
	ipv4.dstAddr;

}

field_list_calculation ipv4_checksum {
	input {
		ipv4_checksum_list;
	}
	algorithm : csum16;
	output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
	verify ipv4_checksum;
	update ipv4_checksum;
}

#define IP_PROT_TC 0x06

parser parse_ipv4 {
	extract(ipv4);

	set_metadata(meta.ipv4SrcAddr, ipv4.srcAddr);
	set_metadata(meta.ipv4DstAddr, ipv4.dstAddr);
	set_metadata(meta.tcpLength, ipv4.totalLen - 20);

	return select(ipv4.protocol) {
		IP_PROT_TCP : parse_tcp;
		default: ingress;
	}
}



header_type tcp_t {
	fields {
		srcPort : 16;
		dstPort : 16;
		seqNo : 32;
		ackNo : 32;
		dataOffset : 4;
        res : 4;
        flags : 3;
		ack: 1;
		psh: 1;
		rst: 1;
		syn: 1;
		fin: 1;		 
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}


header tcp_t tcp;
parser parse_tcp {
	extract(tcp);

	set_metadata(meta.is_Tcp, 1);
	set_metadata(meta.tcp_sp, tcp.srcPort);
	set_metadata(meta.tcp_dp, tcp.dstPort);
	set_metadata(meta.tcp_ack, tcp.ack);
	set_metadata(meta.tcp_psh, tcp.psh);
	set_metadata(meta.tcp_rst, tcp.rst);
	set_metadata(meta.tcp_syn, tcp.syn);
	set_metadata(meta.tcp_fin, tcp.fin);	
	return ingress;
}

field_list tcp_checksum_list {
        ipv4.srcAddr;
        ipv4.dstAddr;
        8'0;
        ipv4.protocol;
        meta.tcpLength;
        tcp.srcPort;
        tcp.dstPort;
        tcp.seqNo;
        tcp.ackNo;
        tcp.dataOffset;
        tcp.res;
        tcp.flags;
		tcp.ack;
		tcp.psh;
		tcp.rst;
		tcp.syn;
		tcp.fin;		 
        tcp.window;
        tcp.urgentPtr;
        payload;
}
field_list_calculation tcp_checksum {
    input {
        tcp_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field tcp.checksum {
    verify tcp_checksum if(valid(tcp));
    update tcp_checksum if(valid(tcp));
}





header_type meta_t{
	fields {
		is_Tcp: 1;

		in_port:8;
		macSrcAddr:48;
		macDstAddr:48;
		ipv4SrcAddr:32;
		ipv4DstAddr:32;
		tcpDp: 16;
		tcpSp: 16;
		tcpLength:16;
		
		reply_type:2;//00 noreply  01 syn/ack  
		tcp_ack:1;
		tcp_psh:1;
		tcp_rst:1;
		tcp_syn:1;
		tcp_fin:1;
		tcp_session_map_index :  13;
		dstip_pktcount_map_index: 13;		
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

control ingress {
	//apply(ipv4_lpm_table);
	
	if (meta.is_Tcp)
	{
	
	
	}
	else
	{
		apply(L2_switch_table);
	}


}
control egress{

}


