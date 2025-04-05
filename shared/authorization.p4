/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// NOTE: new type added here
const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_IPV6 = 0x86DD;
const bit<16> TYPE_EPIC = 0x9010;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;

// Layer 2 headers
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

// EPIC Header
header epic_l1 {
    bit<4> path_ts;
    bit<8> src_as_host;
    bit<3> hop_validation;
    bit<2> segment_id; // Similar to seg_id to hop_validation
    bit<8> packet_ts;
    bit<16> dest_validation;
}

// TODO: Make sure this works (idea on how to have many of these.)
header epic_hop_validation {
    bit<3> hop_validation;
    bit<1> validation_next_hop;
}
// Add this to the parser/deparser

// Layer 3 headers
header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header ipv6_t {
    bit<4> version;
    bit<8> traffClass;
    bit<20> flowLabel;
    bit<16> payloadLen;
    bit<8> nextHeader;
    bit<8> hoplim;
    bit<128> srcAddr;
    bit<128> dstAddr;
}

// Metadata
struct metadata {
    bit<1> consensus;
}

// Headers
struct headers {
    // Layer 2 headers
    ethernet_t ethernet;

    // Layer 3 headers
    ipv4_t ipv4;
    ipv6_t ipv6;

    epic_l1 epic;
}

/*************************************************************************/
/**************************  P A R S E R  ********************************/
/*************************************************************************/

// TODO: Added the consensus parsing function in MyParser
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: parse_ipv4;
            TYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4{
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_CONSENSUS: parse_consensus;
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_ipv6{
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHeader){
            TYPE_CONSENSUS: parse_consensus;
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_consensus {
        packet.extract(hdr.consensus);
        transition select(hdr.consensus.protocol){
            TYPE_TCP : parse_tcp;
            TYPE_UDP : parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

/*************************************************************************/
/**************  C H E C K S U M   V E R I F I C A T I O N  **************/
/*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************/
/*****************  I N G R E S S   P R O C E S S I N G  *****************/
/*************************************************************************/

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    //******************* Consensus Actions ************************//
    action consent(){
        hdr.consensus.allow = hdr.consensus.allow + 1;
    }

    action unconsent(){
        hdr.consensus.allow = hdr.consensus.allow - 1;
    }

    action ipv4_ingress(){
        hdr.consensus.setValid();
        hdr.consensus.protocol = hdr.ipv4.protocol;
        hdr.ipv4.protocol = TYPE_CONSENSUS;
    }

    action ipv6_ingress(){
        hdr.consensus.setValid();
        hdr.consensus.protocol = hdr.ipv6.nextHeader;
        hdr.ipv6.nextHeader = TYPE_CONSENSUS;
    }

    //******************** IP based forwarding ***************************//
    action ipv4_forward(bit<9> port) {
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        standard_metadata.egress_spec = port;
    }

    action ipv6_forward(bit<9> port){
        hdr.ipv6.hoplim = hdr.ipv6.hoplim - 1;
        standard_metadata.egress_spec = port;
    }

    action ipv4_lastHop(bit<9> port){
        // If meta.consensus is not positive, the packet must be dropped
        meta.consensus = (hdr.consensus.allow > 0) ? 1w1 : 1w0;

        // Removing consensus header and forwarding packet
        hdr.ipv4.protocol = hdr.consensus.protocol;
        hdr.consensus.setInvalid();
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        standard_metadata.egress_spec = port;
    }

    action ipv6_lastHop(bit<9> port){
        // If meta.consensus is not positive, the packet must be dropped
        meta.consensus = (hdr.consensus.allow > 0) ? 1w1 : 1w0;

        // Removing consensus header and forwarding packet
        hdr.ipv6.nextHeader = hdr.consensus.protocol;
        hdr.consensus.setInvalid();
        hdr.ipv6.hoplim = hdr.ipv6.hoplim - 1;
        standard_metadata.egress_spec = port;
    }

    // Layer 3 forwarding tables
    table ipv4_forwarding {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }

        actions = {
            ipv4_forward;
            ipv4_lastHop;
            drop;
        }

        size = 1024;
        default_action = drop();
    }

    table ipv6_forwarding {
        key = {
            hdr.ipv6.dstAddr: lpm;
        }

        actions = {
            ipv6_forward;
            ipv6_lastHop;
            drop;
        }

        size = 1024;
        default_action = drop();
    }

    //******************** Consensus tables definitions ***************************//

#ifdef L2_SWITCH
    // Layer 2 consensus table
    table ethernet_consensus {
        key = {
            hdr.ethernet.srcAddr : exact;
            hdr.ethernet.dstAddr : exact;
            hdr.ethernet.etherType : exact;
        }

        actions = {
            consent;
            unconsent;
        }

        size = 1024;
        default_action = unconsent();
    }
#endif

#ifdef L3_SWITCH
    // Layer 3 consensus tables
    table ipv4_consensus {
        key = {
            hdr.ipv4.srcAddr: exact;
        }

        actions = {
            consent;
            unconsent;
        }

        size = 1024;
        default_action = unconsent();
    }

    table ipv6_consensus {
        key = {
            hdr.ipv6.srcAddr: exact;
        }

        actions = {
            consent;
            unconsent;
        }

        size = 1024;
        default_action = unconsent();
    }
#endif

#ifdef L4_SWITCH
    // Layer 4 consensus tables
    table udp_consensus {
        key = {
            hdr.udp.dstPort : exact;
        }

        actions = {
            consent;
            unconsent;
        }

        size = 1024;
        default_action = unconsent();
    }

    table tcp_consensus {
        key = {
            hdr.tcp.dstPort : exact;
        }

        actions = {
            consent;
            unconsent;
        }

        size = 1024;
        default_action = unconsent();
    }
#endif

    apply {
        // Add the consensus header if it doesn't exists
        if(!hdr.consensus.isValid()){
            if(hdr.ipv4.isValid()) ipv4_ingress();
            else ipv6_ingress();
        }

        // Consensus tables
#ifdef L2_SWITCH
        if(hdr.ethernet.isValid()) ethernet_consensus.apply();
#endif

#ifdef L3_SWITCH
        if(hdr.ipv4.isValid()) ipv4_consensus.apply();
        else if(hdr.ipv6.isValid()) ipv6_consensus.apply();
#endif

#ifdef L4_SWITCH
        if(hdr.tcp.isValid()) tcp_consensus.apply();
        else if(hdr.udp.isValid()) udp_consensus.apply();
#endif

        // Packet forwarding
        if(hdr.ipv4.isValid()) ipv4_forwarding.apply();
        else if(hdr.ipv6.isValid()) ipv6_forwarding.apply();
    }
}

/*************************************************************************/
/****************  E G R E S S   P R O C E S S I N G   *******************/
/*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        if(!hdr.consensus.isValid() && meta.consensus == 0){
            // Drop packet
            mark_to_drop(standard_metadata);
        }
    }
}

/*************************************************************************/
/*************   C H E C K S U M    C O M P U T A T I O N   **************/
/*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************/
/***********************  D E P A R S E R  *******************************/
/*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // Should automatically skip any non-valid headers
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.consensus);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************/
/**************************  S W I T C H  ********************************/
/*************************************************************************/


V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;