# EPIC-Authorization
Implementation of Authorization for source routing based on EPIC algorithms

## IPv6 extensions:
The supported IPv6 extension are the following:
- IPv6 Route: with nextheader value 43,
- EPIC: with nextheader value 253, used as testing value.

The recommended order for IPv6 extensions is the following:


| Order | Header Type | Next Header Code |
| ------| ----------- | ---------------- |
|   1   | Basic IPv6 Header |      -     |
|   2   | Hop-by-Hop Options |     0     |
|   3   | Destination Options (with Routing Options) |     60    |
|   4   | Routing Header |     43    |
|   5   | Fragment Header |     44    |
|   6   | Authentication Header |     51    |
|   7   | Encapsulation Security Payload Header |     50    |
|   8   | Destination Options |     60    |
|   9   | Mobility Header |    135    |
|       | No next header |     59    |
| Upper layer | Hop-by-Hop Options |     6     |
| Upper layer | Hop-by-Hop Options |     17    |
| Upper layer | Hop-by-Hop Options |     58    |

as defined by the IETF (Internet Engineering Task Force) in the following RFC standard [RFC 2460](https://datatracker.ietf.org/doc/html/rfc2460).

Regardless of the defined standard, I've decided to support any packet that didn't follow this order, with the only assumptions being that the `Routing Header` is located before the `EPIC header`. Given this requirement, I've defined two header stacks:
```p4
ipv6_ext_base_t[IPV6_EXTENSION_HEADER_SIZE] ipv6_ext_base_before_SR;
ipv6_ext_base_t[IPV6_EXTENSION_HEADER_SIZE] ipv6_ext_base_after_SR;
```

where the size can be chosen during compilation, (I've chosen 8 by default):
```C
#ifndef IPV6_EXTENSION_HEADER_SIZE
    #define IPV6_EXTENSION_HEADER_SIZE 8
#endif
```

The generic IPv6 extenion header is defined as the following:
```p4
// IPv6 extension header structure
header ipv6_ext_base_t {
    bit<8> nextHeader;
    bit<8> hdrExtLen;
    varbit<16320> data; // Maximum size is 255 octets => 8 * 255 = 2040 bytes = 16'320bits
}
```
The data is defined as a varbit since each extenion header can be of different sizes. I've chosen the size to be $16'320$ bits, since the maximum value of 1 byte is 255. Since the *hdrExtLen* express the amount of octets, the maximum value is $8 * 255 = 2040 \text{bytes} = 16'320 \text{bits}$.

### IPv6 extension parsing
The parsing is done as the following:
```p4
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
```

A header in the current state is defined *temp*, the first 16 bits are extracted since they define the next header and the header size, common in all header extenion. Then, the header size is used to calculate then length of the rest of the header and extract it. Then, *temp* is added to the header stack and set valid. Since this are the headers that appear before the routing header, any other header will still enter this state, until the route is parsed. After the route header is parsed, the modified state 
https://github.com/filwastaken/EPIC-Authorization/blob/3cbe6886784691a5e1d2b64ced20eb757151c2d1/shared/authorization.p4#L203-L232

which is essentially the same, execpt the *temp* header is saved in the second header stack:
```p4c
hdr.ipv6_ext_base_after_SR[meta.ext_idx] = temp;
hdr.ipv6_ext_base_after_SR[meta.ext_idx].setValid();
```
### IPv6 extensions deparsing
```p4
apply {
  ...

  // IPv6 extension headers
  packet.emit(hdr.ipv6_ext_base_before_SR);

  // Route header
  ...

  // IPv6 extension headers
  packet.emit(hdr.ipv6_ext_base_after_SR);

  ...
}
```

This logic emits every IPv6 extension header before the segment routing header, then every IPv6 extension header after. In p4, `packet.emit` automatically emits only the valid entries in an header stack.

## Routing header
The routing header is defined as the following:
```p4
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
```

I've divided the fixed part of the extension so that the list of addresses that will be defined in the header can be parsed into an header stack. In particular, I defined the header stack size so that it can be changed via compiler options:
```C
#ifndef IPV6_EXTENSION_HEADER_SIZE
    #define IPV6_EXTENSION_HEADER_SIZE 8
#endif
```

and the header stack as the following:

```p4
route_base_t route_header;
route_segment_list_entry_t[MAX_SRV6_SEGMENTS] segment_list;
```

### Parsing the routing header
To parse the routing header, I've defined to states where the first called [parse_route](/shared/authorization.p4#150) handles the fixed part of the header (namely, [route_base_t](/shared/authorization.p4#64), and the second called [parse_route_list](/shared/authorization.p4#160) parses into the header stack. Most importantly, in the `parse_route` state, I do the following check:

```p4
state parse_route {
  ...

  transition select((hdr.route_jeader.headlerLength / 128) > MAX_SRV6_SEGMENTS) {
    true: reject;
    false: parse_route_list;
  }
}
```

This manages the case where more destinations have been implemented in the routing header than the program can handle (which is directly related ton the size of the header stack). Furthermore, the state `parse_route_list` is defined as the following:

```p4
state parse_route_list {
  packet.extract(hdr.segment_list, (bit<32>) (hdr.route_header.headerLength / 2));

  meta.segment_list_count = hdr.segment_list.lastIndex() + 1;
  meta.ext_idx = 0;

  transition select(hdr.route_header.nextHeader){
    EPIC: parse_epic;
    default: parse_ipv6_ext_chain_after_SR;
  }
}
```

* The `packet.extract` function automatically saves the addresses into the header stack,
* The `meta.segment_list_count` is used to calculate the number of provided destination list, needed for the routing action in the ingress control block,
* The `meta.ext_idx` assignment is used for [IPv6 parsing](#ipv6-extension-parsing) to reset the index of the header stack and re-use it, saving space.

### Routing ingress processing
The match-action table for the routing header is defined as the following:
```p4
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
```
By default, every switch should have an entry for every direct neighbor such that the IP address of the neighbor should trigger the ***nextDestination*** action, which is defined as the following:
```p4
action nextDestination() {
  bit<8> index = meta.segment_list_count - hdr.route_header.segmentsLeft;
  hdr.ipv6.dstAddr = hdr.segment_list[index].address;
  hdr.route_header.segmentsLeft = hdr.route_header.segmentsLeft - 1;
}
```
This action will get the next address from the segments and swap it with the destination of the IPv6 header. Consider that the destination port will still sent the packet towards the destination before the swap since the ipv6 forwarding applies before the routing action. The routing apply block is the following:

