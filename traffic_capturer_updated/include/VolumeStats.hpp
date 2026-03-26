#pragma once
#include <cstdint>

// ---------------------------------------------------------------------------
// VolumeStats — O(1) packet and byte count statistics.
//
// Tracks:
//   total_fwd_pkts  → Total Fwd Packets [23]  (also Subflow Fwd Packets [37])
//   total_bwd_pkts  → Total Backward Packets [31] (also Subflow Bwd Packets [29])
//   total_packets   → used for Average Packet Size in FeatureExtractor
//
// Rates (Bwd Packets/s [7], Fwd Packets/s) are computed at extract time
// using flow duration — NOT tracked here, as duration is only known at expiry.
//
// Down/Up Ratio = bwd_pkts / fwd_pkts — computed at extract time.
// ---------------------------------------------------------------------------
struct VolumeStats {

    uint64_t total_fwd_pkts{0};    // [23] Total Fwd Packets
    uint64_t total_bwd_pkts{0};    // [31] Total Backward Packets
    uint64_t total_packets{0};     // all packets (fwd + bwd)

    // Update — O(1)
    inline void update(bool forward) noexcept {
        total_packets++;
        if (forward) total_fwd_pkts++;
        else         total_bwd_pkts++;
    }

    // ── Feature accessors ─────────────────────────────────────────────────

    // [23] Total Fwd Packets  (also Subflow Fwd Packets [37])
    uint64_t total_fwd_packets() const noexcept { return total_fwd_pkts; }

    // [31] Total Backward Packets  (also Subflow Bwd Packets [29])
    uint64_t total_bwd_packets() const noexcept { return total_bwd_pkts; }

    // Used by FeatureExtractor for:
    //   Average Packet Size  = total_bytes / total_packets
    //   Bwd Packets/s        = total_bwd_pkts / duration_sec
    //   Fwd Packets/s        = total_fwd_pkts / duration_sec
    //   Down/Up Ratio        = total_bwd_pkts / total_fwd_pkts
    uint64_t total_pkt_count()  const noexcept { return total_packets;  }
};