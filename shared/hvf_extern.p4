extern hvf_mac {
    // Constructor: for setup
    hvf_mac();

    bit<24> compute_hvf(
        bit<64> tspkt,
        bit<64> src,
        bit<128> hop_authenticator
    );
}