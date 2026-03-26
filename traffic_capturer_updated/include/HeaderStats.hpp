#pragma once
#include <cstdint>

// ---------------------------------------------------------------------------
// HeaderStats — O(1) header length accumulation.
//
// CICFlowMeter definition:
//   Fwd Header Length = sum of (ip_header_len + tcp_header_len) for all fwd pkts
//   Bwd Header Length = sum of (ip_header_len + tcp_header_len) for all bwd pkts
//
// For UDP: tcp_header_len = 8 (UDP header size)
// For ICMP/other: tcp_header_len = 0
//
// Fwd Header Length.1 is an exact duplicate of Fwd Header Length —
// it's a CSV artifact from CICFlowMeter. FeatureExtractor outputs the
// same value twice under both names.
// ---------------------------------------------------------------------------
struct HeaderStats {

    uint64_t fwd_header_bytes{0};   // [12] Fwd Header Length
                                    // [17] Fwd Header Length.1  (same value)
    uint64_t bwd_header_bytes{0};   // [8]  Bwd Header Length

    // Update — O(1), no allocation
    // l4_header_len: tcp_header_len for TCP, 8 for UDP, 0 for ICMP/other
    inline void update(uint16_t ip_header_len,
                       uint16_t l4_header_len,
                       bool     forward) noexcept
    {
        const uint32_t total = static_cast<uint32_t>(ip_header_len)
                             + static_cast<uint32_t>(l4_header_len);
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
    uint64_t fwd_header_length() const noexcept { return fwd_header_bytes; }
};