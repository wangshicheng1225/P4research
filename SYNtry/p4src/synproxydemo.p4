

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
header_type tcp_options_t {
    fields {
	kind : 8;
	option_length : 8;
	mss : 16;
    }
}

header tcp_options_t tcp_options;

parser start {
	
	set_metadata(meta.in_port, standard_metadata.ingress_port);

	//register_write(temp_write,
	//		   9,
	//		   meta.in_port);
	return  parse_ethernet;
	
}

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806

header ethernet_t ethernet;

parser parse_ethernet {
	extract(ethernet);
	set_metadata(meta.eth_da,ethernet.dstAddr);
	set_metadata(meta.eth_sa,ethernet.srcAddr);
	set_metadata(meta.eth_type,ethernet.etherType);
	return select(latest.etherType) {
		ETHERTYPE_IPV4 : parse_ipv4;
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

#define IP_PROT_TCP 0x06

parser parse_ipv4 {
	extract(ipv4);
	
	set_metadata(meta.ipv4_sa, ipv4.srcAddr);
	set_metadata(meta.ipv4_da, ipv4.dstAddr);
	set_metadata(meta.ip_proto, ipv4.protocol);
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
	set_metadata(meta.tcp_sp, tcp.srcPort);
	set_metadata(meta.tcp_dp, tcp.dstPort);
	set_metadata(meta.tcp_ack, tcp.ack);
	set_metadata(meta.tcp_psh, tcp.psh);
	set_metadata(meta.tcp_rst, tcp.rst);
	set_metadata(meta.tcp_syn, tcp.syn);
	set_metadata(meta.tcp_fin, tcp.fin);	
	set_metadata(meta.tcp_seq, tcp.seqNo);	
	extract(tcp_options);
	return ingress;
}
field_list tcp_checksum_list {
        ipv4.srcAddr;
        ipv4.dstAddr;
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


header_type intrinsic_metadata_t {
	fields {
		mcast_grp:4;
		egress_rid:4;
		mcast_hash:16;
		lf_field_list:32;
			
	}
}

metadata intrinsic_metadata_t intrinsic_metadata;

header_type meta_t {
	fields {
		do_forward : 1;
	eth_sa:48;
	eth_da:48;
	eth_type:16;
        ipv4_sa : 32;
        ipv4_da : 32;
        ip_proto : 8;
        tcp_sp : 16;
        tcp_dp : 16;
        nhop_ipv4 : 32;
        if_ipv4_addr : 32;
        if_mac_addr : 48;
        is_ext_if : 1;
        tcpLength : 16;
        in_port : 8;
	
		reply_type:2;//00 noreply  01 syn/ack  
		tcp_ack:1;
		tcp_psh:1;
		tcp_rst:1;
		tcp_syn:1;
		tcp_fin:1;
		tcp_seq:32;
		tcp_session_map_index :  13;
		dstip_pktcount_map_index: 13;
								 
		tcp_session_id : 16;
		
		dstip_pktcount:32;	 
	

		tcp_session_is_SYN: 8;// this session has sent a syn to switch
		tcp_session_is_ACK: 8;// this session has sent a ack to switch
		
	}

}

metadata meta_t meta;

field_list l3_hash_fields {

    ipv4.srcAddr;   
	ipv4.dstAddr;
	ipv4.protocol;
	tcp.srcPort;	

	tcp.dstPort;
}
field_list_calculation tcp_session_map_hash {
	input {
		l3_hash_fields;
	}
	algorithm: crc16;
	output_width: 13;
}

field_list dstip_hash_fields {
	ipv4.dstAddr;
}

field_list_calculation dstip_map_hash {
	input {
		dstip_hash_fields;
	}
	algorithm:crc16;
	output_width:13;
}

register tcp_session_is_SYN {
	width : 8;
	instance_count: 8192;
}

register tcp_session_is_ACK {
	width : 8;
	instance_count: 8192;
}

register h1_seq {
	width: 32;
	instance_count: 8192;
}

register h2_ack {
	width: 32;
	instance_count: 8192;
}

register dstip_pktcount {
	width : 32; 
	instance_count: 8192;
}


register temp_hash {
	width:32;
	instance_count: 10;
}

register temp_write {
	width:32;
	instance_count: 10;
	
}


action _drop() {
	drop();
}
action lookup_session_map()
{
	modify_field_with_hash_based_offset(meta.tcp_session_map_index,0,
										tcp_session_map_hash, 13);

	modify_field_with_hash_based_offset(meta.dstip_pktcount_map_index,0,
											dstip_map_hash,13);

	//dstip_pktcount_map_index : 13;
	
	register_read(meta.dstip_pktcount,
				 dstip_pktcount, meta.dstip_pktcount_map_index);

	
	add_to_field(meta.dstip_pktcount,  1);

	register_write(dstip_pktcount,
				   meta.dstip_pktcount_map_index,
					meta.dstip_pktcount);

	register_write(temp_write,
			   1,
			   meta.dstip_pktcount);



	register_read(meta.tcp_session_is_SYN,
				  tcp_session_is_SYN, meta.tcp_session_map_index);
	
	register_read(meta.tcp_session_is_ACK,
				  tcp_session_is_ACK, meta.tcp_session_map_index);

}

table session_check {
	actions { lookup_session_map;}
}

action init_session()
{
	modify_field(meta.reply_type,3);
	register_write(tcp_session_is_SYN, meta.tcp_session_map_index,
					1);
	register_write(tcp_session_is_ACK, meta.tcp_session_map_index,0);
	register_write(h1_seq, meta.tcp_session_map_index,meta.tcp_seq);

}

table session_init_table {
	actions { init_session; }
	
}

action complete_session()
{
	modify_field(meta.reply_type,2);

	register_write(tcp_session_is_SYN, meta.tcp_session_map_index,
					1);
	register_write(tcp_session_is_ACK, meta.tcp_session_map_index,1);

	
}
table session_complete_table {
	actions { complete_session;}
}


action setsyn_ack(port)
{
	modify_field(tcp.syn,1);
	modify_field(tcp.ack,1);
	modify_field(tcp.seqNo, meta.dstip_pktcount);
	modify_field(standard_metadata.egress_spec, port);

}
action sendback_sa()
{
	modify_field(tcp.syn,1);
	modify_field(tcp.ack,1);
	modify_field(tcp.seqNo,0x0) ;
	
	modify_field(tcp.ackNo,meta.tcp_seq);
	add_to_field(tcp.ackNo,1);
	modify_field(ipv4.dstAddr, meta.ipv4_sa);
	modify_field(ipv4.srcAddr, meta.ipv4_da);
	modify_field(tcp.srcPort, meta.tcp_dp);
	modify_field(tcp.dstPort, meta.tcp_sp);
	modify_field(ethernet.dstAddr, meta.eth_sa);
	modify_field(ethernet.srcAddr, meta.eth_da);
		
	modify_field(standard_metadata.egress_spec, meta.in_port);

}

action sendback_session_construct()
{
	modify_field(tcp.fin,1);
	modify_field(standard_metadata.egress_spec, meta.in_port);

}

action dump(){
	//We can print some msg here to debug.

 	//register_write(temp_write,6,standard_metadata.egress_spec);
 	//register_write(temp_write,5,meta.in_port);
 	//register_write(temp_write,4,1);
}

table dump_table{
	actions {dump;}
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

action setack(port)
{
	register_read(meta.tcp_seq,h1_seq, meta.tcp_session_map_index);
	modify_field(ipv4.totalLen,44);
	modify_field(tcp.syn,1);
	modify_field(tcp.ack,0);
	modify_field(tcp.seqNo,meta.tcp_seq);
	modify_field(tcp.ackNo, 0);
	modify_field(tcp.dataOffset, 6);
	add_header(tcp_options);
	modify_field(tcp_options.mss, 1460);
	modify_field(tcp_options.kind, 2);
	modify_field(tcp_options.option_length, 4);
	modify_field(standard_metadata.egress_spec, port);
}

table forward_table{
	reads{
		meta.reply_type:exact;
	}

	actions{
		setsyn_ack;
		setack;
		sendback_sa;
		sendback_session_construct;

		_drop;
	
	}
}
/*
 *
		tcp_ack:1;
		tcp_psh:1;
		tcp_rst:1;
		tcp_syn:1;
		tcp_fin:1;
 *
 * */

control ingress {
	if(meta.eth_type == ETHERTYPE_ARP or meta.ip_proto != IP_PROT_TCP){
		apply(L2_switch_table);
	} 
	else if(meta.eth_type == ETHERTYPE_IPV4) 
	{
		apply(session_check);
		if( meta.tcp_syn == 1 and meta.tcp_ack == 1){

		}
		else if (meta.tcp_syn == 1 /*and meta.dstip_pktcount < 4 */)
		{
			if (meta.tcp_session_is_SYN==0 and meta.tcp_session_is_ACK==0)
			{
				apply(session_init_table);
			}

		}
		else if (meta.tcp_ack==1 /*and meta.dstip_pktcount < 4*/) 
		{
			if (meta.tcp_session_is_SYN == 1 and meta.tcp_session_is_ACK == 0)
			{
				apply(session_complete_table);
			}
		}

		apply(forward_table);	
	}
}

control egress {
	apply(dump_table);
}



