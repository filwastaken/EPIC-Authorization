/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
// Layer 2 definitions
const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_IPV6 = 0x86DD;

// Layer 3 definitions
const bit<8> HOPOPT = 0;
const bit<8> IPV6_ROUTE = 43;
const bit<8> IPV6_FRAG = 44;
const bit<8> ESP = 50;
const bit<8> AH = 51;
const bit<8> IPV6_OPTS = 60;
const bit<8> MOBILITY_HEADER = 135;
const bit<8> HIP = 139;
const bit<8> SHIM6 = 140;
const bit<8> BIT_EMU = 147;
const bit<8> EPIC = 253;

#ifndef MAX_SRV6_SEGMENTS
    #define MAX_SRV6_SEGMENTS 10
#endif

#ifndef IPV6_EXTENSION_HEADER_SIZE
    #define IPV6_EXTENSION_HEADER_SIZE 8
#endif

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

// IPv6 header
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

// IPv6 extension header structure
header ipv6_ext_base_t {
    bit<8> nextHeader;
    bit<8> hdrExtLen;
    varbit<16320> data; // Maximum size is 255 octets => 8 * 255 = 2040 bytes = 16'320bits
}

// Routing extension header
header route_base_t {
    bit<8>  nextHeader;
    bit<8>  headerLength;   // Length in 8-octet units, minus first 8 octets
    bit<8>  routingType;
    bit<8>  segmentsLeft;   // Index (0..N-1) of the next segment to process
    bit<8>   last_entry;
    bit<8>   flags;
    bit<16>  tag;
}

header route_segment_list_entry_t {
    bit<128> address;
}

// EPIC Header
header epicl1_t {
    bit<32> path_ts;
    bit<64> src_as_host;
    bit<64> packet_ts;

    bit<8> per_hop_count;       // Used to loop (with recursion) over the hop validations 
    bit<8> nextHeader;          // Added nextHeader to the paper implementation
    // destination validation is unused in l1
}

header epicl1_per_hop_t {
    bit<24> hop_validation;
    bit<16> segment_id;
}

// Metadata
struct metadata {
    bit<4> ext_idx;
    bit<4> segment_list_count;
}

// Headers
struct headers {
    // Layer 2 headers
    ethernet_t ethernet;

    // IPv6 headers
    ipv6_t ipv6;

    // IPv6 extensions
    ipv6_ext_base_t[IPV6_EXTENSION_HEADER_SIZE] ipv6_ext_base_before_SR;
    ipv6_ext_base_t[IPV6_EXTENSION_HEADER_SIZE] ipv6_ext_base_after_SR;

    // Route headers
    route_base_t route_header;
    route_segment_list_entry_t[MAX_SRV6_SEGMENTS] segment_list;

    // EPIC headers
    epicl1_t epic;
    epicl1_per_hop_t epic_per_hop_1;
    epicl1_per_hop_t epic_per_hop_2;
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
            TYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv6{
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHeader){
            IPV6_ROUTE: parse_route;
            EPIC: parse_epic;
            default: parse_ipv6_ext_chain_before_SR;
        }
    }

    state parse_route {
        packet.extract(hdr.route_header);

        // TODO: Do the math for handling the number of segments in the header 
        transition select((hdr.route_header.headerLength / 128) > MAX_SRV6_SEGMENTS) {
            true: reject;
            false: parse_route_list;
        }
    }

    state parse_route_list {
        packet.extract(hdr.segment_list, (bit<32>) (hdr.route_header.headerLength / 2));

        meta.segment_list_count = hdr.segment_list.lastIndex() + 1;
        meta.ext_idx = 0;

        transition select(hdr.route_header.nextHeader){
            EPIC: parse_epic;
            default: parse_ipv6_ext_chain_after_SR;
        }
    }

    state parse_ipv6_ext_chain_before_SR {
        ipv6_ext_base_t temp;
        packet.extract(temp, 16);

        // Extract variable size                                          Removing the 2 bytes already extracted
        bit<32> len = ((bit<32>) (temp.hdrExtLen + 1) * 8) - 2;
        packet.extract(temp, len * 8);

        hdr.ipv6_ext_base_before_SR[meta.ext_idx] = temp;
        hdr.ipv6_ext_base_before_SR[meta.ext_idx].setValid();

        meta.ext_idx = meta.ext_idx + 1;

        transition select(temp.nextHeader) {
            HOPOPT: parse_ipv6_ext_chain_before_SR;
            IPV6_ROUTE: parse_route;
            IPV6_FRAG: parse_ipv6_ext_chain_before_SR;
            ESP: parse_ipv6_ext_chain_before_SR;
            AH: parse_ipv6_ext_chain_before_SR;
            IPV6_OPTS: parse_ipv6_ext_chain_before_SR;
            MOBILITY_HEADER: parse_ipv6_ext_chain_before_SR;
            HIP: parse_ipv6_ext_chain_before_SR;
            SHIM6: parse_ipv6_ext_chain_before_SR;
            BIT_EMU: parse_ipv6_ext_chain_before_SR;

            // parse epic
            EPIC: parse_epic;

            default: accept;
        }
    }

    state parse_ipv6_ext_chain_after_SR {
        ipv6_ext_base_t temp;
        packet.extract(temp, 16);

        // Extract variable size                                          Removing the 2 bytes already extracted
        bit<32> len = ((bit<32>) (temp.hdrExtLen + 1) * 8) - 2;
        packet.extract(temp, len * 8);

        hdr.ipv6_ext_base_after_SR[meta.ext_idx] = temp;
        hdr.ipv6_ext_base_after_SR[meta.ext_idx].setValid();

        meta.ext_idx = meta.ext_idx + 1;

        transition select(temp.nextHeader) {
            HOPOPT: parse_ipv6_ext_chain_after_SR;
            IPV6_FRAG: parse_ipv6_ext_chain_after_SR;
            ESP: parse_ipv6_ext_chain_after_SR;
            AH: parse_ipv6_ext_chain_after_SR;
            IPV6_OPTS: parse_ipv6_ext_chain_after_SR;
            MOBILITY_HEADER: parse_ipv6_ext_chain_after_SR;
            HIP: parse_ipv6_ext_chain_after_SR;
            SHIM6: parse_ipv6_ext_chain_after_SR;
            BIT_EMU: parse_ipv6_ext_chain_after_SR;

            // parse epic
            EPIC: parse_epic;

            default: accept;
        }
    }

    state parse_epic {
        packet.extract(hdr.epic);
        transition parse_first_epic_hop;

        /* I don't think this is necessary
        transition select(hdr.epic.per_hop_count){
            0: reject;
            default: parse_first_epic_hop;
        }*/
    }

    state parse_first_epic_hop {
        packet.extract(hdr.epic_per_hop_1);
        transition select(hdr.epic.per_hop_count){
            0: reject;
            1: accept;
            default: parse_second_epic_hop; // hop_count > 1
        }
    }

    state parse_second_epic_hop {
        packet.extract(hdr.epic_per_hop_2);
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

    //******************** IP based forwarding ***************************//
    action ipv6_forward(bit<9> port){
        hdr.ipv6.hoplim = hdr.ipv6.hoplim - 1;
        standard_metadata.egress_spec = port;
    }

    //******************** Routing header forwarding ***************************//
    action nextDestination() {
        bit<8> index = meta.segment_list_count - hdr.route_header.segmentsLeft;
        hdr.ipv6.dstAddr = hdr.segment_list[index].address;
        hdr.route_header.segmentsLeft = hdr.route_header.segmentsLeft - 1;
    }

    // EPIC function idea, still to implement
    action epic_hop() {
        hdr.epic.per_hop_count = hdr.epic.per_hop_count - 1;
    }

    action epic_later_header() {
        hdr.ipv6_ext_base_after_SR[meta.ext_idx].nextHeader = hdr.epic.nextHeader;
        hdr.epic.setInvalid();
        hdr.epic_per_hop_1.setInvalid();
    }

    action epic_first_header() {
        hdr.ipv6.nextHeader = hdr.epic.nextHeader;
        hdr.epic.setInvalid();
        hdr.epic_per_hop_1.setInvalid();
    }

    action check_hop_validation(){
        // TODO:
        // Calculate the MAC and check whether it is correct with the one provided in the header
    }

    // IPv6 table
    table ipv6_forwarding {
        key = {
            hdr.ipv6.dstAddr: lpm;
        }

        actions = {
            ipv6_forward;
            drop;
        }

        size = 1024;
        default_action = drop();
    }

    // Routing table
    table routing_forwarding {
        key = {
            hdr.ipv6.dstAddr: exact;
        }

        actions = {
            nextDestination;
            NoAction;
        }

        default_action = NoAction();
    }

    // EPIC tables
    table epic_authorization {
        key = {
            // TODO, based on extern function available
        }

        actions = {
            check_hop_validation;
            drop;
        }

        size = 1024;
        default_action = drop();
    }

    table epic_structure {
        key = {
            hdr.epic.per_hop_count: exact;
            hdr.ipv6.nextHeader: exact;
        }

        actions = {
            epic_hop;
            epic_later_header;
            epic_first_header;
            drop;
        }

        size = 1024;
        default_action = epic_hop();
    }

    apply {
        // Packet forwarding
        if(hdr.ipv6.isValid()) {
            if(hdr.route_header.isValid() && hdr.route_header.segmentsLeft > 0) {
                routing_forwarding.apply();
            }

            ipv6_forwarding.apply();
        }


        if(hdr.epic.isValid()) {
            epic_authorization.apply();
            epic_structure.apply();
        }
    }
}

/*************************************************************************/
/****************  E G R E S S   P R O C E S S I N G   *******************/
/*************************************************************************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {

    }
}

/*************************************************************************/
/*************   C H E C K S U M    C O M P U T A T I O N   **************/
/*************************************************************************/
control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
    }
}

/*************************************************************************/
/***********************  D E P A R S E R  *******************************/
/*************************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // Should automatically skip any non-valid headers
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv6);

        // IPv6 extension headers
        packet.emit(hdr.ipv6_ext_base_before_SR);

        // Route header
        packet.emit(hdr.route_header);
        packet.emit(hdr.segment_list);

        // IPv6 extension headers
        packet.emit(hdr.ipv6_ext_base_after_SR);

        packet.emit(hdr.epic);
        // epic_per_hop_1 shoduln't be emitted since it's valid only for this border router
        packet.emit(hdr.epic_per_hop_2);
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