#pragma once
#include "RunningStats.hpp"
#include <cstdint>

// ---------------------------------------------------------------------------
// LengthStats — O(1) per-packet packet length statistics.
//
// Uses ip_total_len (from IP header) for ALL length calculations,
// matching CICFlowMeter semantics exactly.
//
// Three RunningStats instances:
//   flow_len  → all packets  (Packet Length Mean/Std/Variance, Min, Max)
//   fwd_len   → fwd packets  (Fwd Packet Length Mean/Std/Max/Min)
//   bwd_len   → bwd packets  (Bwd Packet Length Mean/Std/Max/Min)
//
// Plain accumulators:
//   fwd_total_bytes → Total Length of Fwd Packets / Subflow Fwd Bytes
//   bwd_total_bytes → Total Length of Bwd Packets / Subflow Bwd Bytes
// ---------------------------------------------------------------------------
struct LengthStats {
    RunningStats flow_len;          // all packets
    RunningStats fwd_len;           // forward packets only
    RunningStats bwd_len;           // backward packets only

    uint64_t fwd_total_bytes{0};    // sum of ip_total_len for fwd packets
    uint64_t bwd_total_bytes{0};    // sum of ip_total_len for bwd packets

    // Update with one packet — O(1), no allocation
    inline void update(uint16_t ip_total_len, bool forward) noexcept {
        const double len = static_cast<double>(ip_total_len);
        flow_len.update(len);
        if (forward) {
            fwd_len.update(len);
            fwd_total_bytes += ip_total_len;
        } else {
            bwd_len.update(len);
            bwd_total_bytes += ip_total_len;
        }
    }

    // ── Feature accessors (CIC exact names) ───────────────────────────────

    // [0]  Bwd Packet Length Std
    double bwd_pkt_len_std()    const noexcept { return bwd_len.stddev();     }

    // [1]  Bwd Packet Length Min
    double bwd_pkt_len_min()    const noexcept { return bwd_len.safe_min();   }

    // [4]  Bwd Packet Length Mean  (also Avg Bwd Segment Size [9] — same value)
    double bwd_pkt_len_mean()   const noexcept { return bwd_len.safe_mean();  }

    // [10] Packet Length Mean
    double pkt_len_mean()       const noexcept { return flow_len.safe_mean(); }

    // [11] Packet Length Variance
    double pkt_len_variance()   const noexcept { return flow_len.variance();  }

    // [13] Bwd Packet Length Max
    double bwd_pkt_len_max()    const noexcept { return bwd_len.safe_max();   }

    // [18] Packet Length Std
    double pkt_len_std()        const noexcept { return flow_len.stddev();    }

    // [19] Total Length of Fwd Packets  (also Subflow Fwd Bytes [25])
    uint64_t total_len_fwd()    const noexcept { return fwd_total_bytes;      }

    // [21] Fwd Packet Length Max
    double fwd_pkt_len_max()    const noexcept { return fwd_len.safe_max();   }

    // [28] Max Packet Length
    double max_pkt_len()        const noexcept { return flow_len.safe_max();  }

    // [30] Min Packet Length
    double min_pkt_len()        const noexcept { return flow_len.safe_min();  }

    // [35] Fwd Packet Length Mean  (also Avg Fwd Segment Size — same value)
    double fwd_pkt_len_mean()   const noexcept { return fwd_len.safe_mean();  }

    // Fwd Packet Length Min  (used in FeatureExtractor)
    double fwd_pkt_len_min()    const noexcept { return fwd_len.safe_min();   }

    // Fwd Packet Length Std
    double fwd_pkt_len_std()    const noexcept { return fwd_len.stddev();     }

    // [27] Total Length of Bwd Packets  (also Subflow Bwd Bytes)
    uint64_t total_len_bwd()    const noexcept { return bwd_total_bytes;      }

    // [2]  Average Packet Size — computed at extract time by FeatureExtractor:
    //      (fwd_total_bytes + bwd_total_bytes) / total_packets
    //      CICFlowMeter computes this from totals, not from running mean.
};