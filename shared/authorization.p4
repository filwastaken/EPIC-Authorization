/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// NOTE: new type added here
const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_IPV6 = 0x86DD;

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

header ipv6_ext_base_t {
    bit<8> nextHeader;
    bit<8> hdrExtLen;
}

// EPIC Header
header epicl1_t {
    bit<4> path_ts;
    bit<8> src_as_host;
    bit<4> hop_validation_count;    // Follow IPv6 extensions header 
    bit<4> segment_id_count;        // ^^
    bit<8> packet_ts;
    bit<16> dest_validation;
}

header epic_hopValidation_t {
    bit<3> hop_validation;
}

header epic_segId_t {
    bit<2> segment_id;
}

// Metadata
struct metadata {
    bit<8> hopVal_index;
    bit<8> segId_index;
}

// Headers
struct headers {
    // Layer 2 headers
    ethernet_t ethernet;

    // Layer 3 headers
    ipv4_t ipv4;
    ipv6_t ipv6;
    ipv6_ext_base_t ipv6_ext;

    epicl1_t epic;
    epic_hopValidation_t epic_hopVal;
    epic_segId_t epic_segId;
}

/*************************************************************************/
/**************************  P A R S E R  ********************************/
/*************************************************************************/
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
            TYPE_EPIC: parse_epic;
            default: accept;
        }
    }

    state parse_ipv6{
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHeader){
            TYPE_EPIC: parse_epic;
            default: parse_ipv6_ext_chain;
        }
    }

    state parse_ipv6_ext_chain {
        packet.extract(hdr.ext_base);

        // Calculate length to skip (8 * (hdrExtLen + 1))
        bit<8> len = (hdr.ext_base.hdrExtLen + 1) * 8;
        packet.advance(len - 2); // already extracted 2 bytes

        transition select(hdr.ext_base.nextHeader) {
            EPIC_NEXT_HEADER: parse_epic;
            default: parse_ipv6_ext_chain;
            // TODO
            // SOLVE THIS CAUSE AT THE MOMENT IS AN INFINITE CHAIN
        }
    }

    state parse_epic {
        packet.extract(hdr.epic);
        transition parse_epic_hopVal;
    }

    state parse_epic_hopVal {
        meta.hopVal_index = meta.hopVal_index + 1;
        packet.extract(hdr.epic_hopVal);
        transition select(meta.hopVal_index < hdr.epic.hop_validation_count){
            true: parse_epic_hopVal;
            false: parse_epic_segId;
        }
    }

    state parse_epic_segId {
        meta.segId_index = meta.segId_index + 1;
        packet.extract(hdr.epic_segId);
        transition select(meta.segId_index < hdr.epic.hop_validation_count){
            true: parse_epic_segId;
            false: accept;
        }
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
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        standard_metadata.egress_spec = port;
    }

    action ipv6_lastHop(bit<9> port){
        // If meta.consensus is not positive, the packet must be dropped
        meta.consensus = (hdr.consensus.allow > 0) ? 1w1 : 1w0;
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

    apply {
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
        if(!hdr.consensus.isValid()){
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