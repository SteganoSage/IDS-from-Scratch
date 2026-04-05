#pragma once
#include <cstdint>

// ---------------------------------------------------------------------------
// HeaderStats — O(1) header length accumulation.
//
// FIX: CICFlowMeter's "Fwd Header Length" / "Bwd Header Length" tracks
// only the L4 (transport) header bytes — NOT the IP header.
//
// Evidence from CIC-IDS 2018 training data:
//   BruteForce flows: avg header per fwd pkt = 32.0
//   This matches TCP header with timestamp option (32 bytes).
//   If IP header (20) were included, avg would be 52+.
//
// Also: In the CIC-IDS 2018 CSV, "Fwd Seg Size Min" is an exact
// duplicate of "Fwd Header Len" (verified: 5000/5000 match in test.csv).
// FeatureExtractor uses fwd_header_length() for both features.
//
// For UDP: l4_header_len = 8 (UDP header size)
// For ICMP/other: l4_header_len = 0
// ---------------------------------------------------------------------------
struct HeaderStats {

    uint64_t fwd_header_bytes{0};   // [12] Fwd Header Length
                                    // [17] Fwd Header Length.1  (same value)
    uint64_t bwd_header_bytes{0};   // [8]  Bwd Header Length

    // Update — O(1), no allocation
    // FIX: Only count L4 header, not IP header, matching CICFlowMeter.
    // ip_header_len is still passed for API consistency but not used here.
    inline void update(uint16_t ip_header_len,
                       uint16_t l4_header_len,
                       bool     forward) noexcept
    {
        (void)ip_header_len;  // not used — CIC only counts L4 header
        const uint32_t total = static_cast<uint32_t>(l4_header_len);
        if (forward)
            fwd_header_bytes += total;
        else
            bwd_header_bytes += total;
    }

    // ── Feature accessors ─────────────────────────────────────────────────

    // [8]  Bwd Header Length
    uint64_t bwd_header_length() const noexcept { return bwd_header_bytes; }

    // [12] Fwd Header Length
    // [17] Fwd Header Length.1  (alias — same value, output twice in extractor)
    // [59] Fwd Seg Size Min — CIC-IDS 2018: identical to Fwd Header Len
    uint64_t fwd_header_length() const noexcept { return fwd_header_bytes; }
};