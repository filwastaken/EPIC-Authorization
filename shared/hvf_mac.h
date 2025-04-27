#ifndef HVF_MAC_H
#define HVF_MAC_H

#include <stdint.h>

// compute_hvf:
//  - tspkt: first parameter 64bits long
//  - src: second first parameter 64bits long
//  - hop_authentication: 128 bits key
//  - mac_out: 3 bytes output buffer

void compute_hvf(uint64_t tspkt, uint64_t src, const uint8_t hop_authentication[16], uint8_t mac_out[3]);

#endif // HVF_MAC_H