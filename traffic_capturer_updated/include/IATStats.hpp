#pragma once
#include "RunningStats.hpp"
#include <cstdint>
#include <limits>

// ---------------------------------------------------------------------------
// IATStats — O(1) inter-arrival time statistics.
//
// Inter-arrival time (IAT) = time gap between consecutive packets.
// All timestamps in microseconds (uint64_t).
//
// Tracks:
//   flow_iat   → gaps between ANY consecutive packets (Flow IAT Max)
//   fwd_iat    → gaps between consecutive FWD packets (Fwd IAT Mean/Max/Min/Std)
//   bwd_iat    → gaps between consecutive BWD packets (Bwd IAT Mean/Std/Max/Min)
//   bwd_iat_total → sum of all bwd IATs (Bwd IAT Total)
//   fwd_iat_total → sum of all fwd IATs (Fwd IAT Total — not in top 38
//                   but tracked for free, costs nothing)
//
// First packet in each direction has no IAT to record — we just store
// its timestamp and wait for the second packet.
//
// CICFlowMeter uses 1,000,000 µs (1 second) as the activity threshold
// for Active/Idle detection — that lives in ActivityStats, not here.
// IATStats purely tracks the raw gaps.
// ---------------------------------------------------------------------------
struct IATStats {

    RunningStats flow_iat;          // all consecutive-packet gaps
    RunningStats fwd_iat;           // fwd-only consecutive gaps
    RunningStats bwd_iat;           // bwd-only consecutive gaps

    uint64_t fwd_iat_total{0};      // sum of all fwd IATs
    uint64_t bwd_iat_total{0};      // sum of all bwd IATs (Bwd IAT Total [32])

    // Sentinel: 0 means "not yet seen first packet in this direction"
    uint64_t last_pkt_ts{0};        // timestamp of last packet (any direction)
    uint64_t last_fwd_ts{0};        // timestamp of last fwd packet
    uint64_t last_bwd_ts{0};        // timestamp of last bwd packet

    bool first_pkt_seen{false};     // has any packet been seen?
    bool first_fwd_seen{false};     // has any fwd packet been seen?
    bool first_bwd_seen{false};     // has any bwd packet been seen?

    // Update with one packet — O(1), no allocation
    inline void update(uint64_t ts_us, bool forward) noexcept {
        // ── Flow IAT: gap from last packet of any direction ───────────────
        if (first_pkt_seen) {
            // Guard against out-of-order timestamps (take absolute diff)
            uint64_t gap = (ts_us >= last_pkt_ts)
                           ? ts_us - last_pkt_ts
                           : last_pkt_ts - ts_us;
            flow_iat.update(static_cast<double>(gap));
        }
        first_pkt_seen = true;
        last_pkt_ts    = ts_us;

        // ── Directional IAT ───────────────────────────────────────────────
        if (forward) {
            if (first_fwd_seen) {
                uint64_t gap = (ts_us >= last_fwd_ts)
                               ? ts_us - last_fwd_ts
                               : last_fwd_ts - ts_us;
                fwd_iat.update(static_cast<double>(gap));
                fwd_iat_total += gap;
            }
            first_fwd_seen = true;
            last_fwd_ts    = ts_us;
        } else {
            if (first_bwd_seen) {
                uint64_t gap = (ts_us >= last_bwd_ts)
                               ? ts_us - last_bwd_ts
                               : last_bwd_ts - ts_us;
                bwd_iat.update(static_cast<double>(gap));
                bwd_iat_total += gap;
            }
            first_bwd_seen = true;
            last_bwd_ts    = ts_us;
        }
    }

    // ── Feature accessors (CIC exact names, top-38 index in comments) ────

    // [22] Fwd IAT Mean
    double fwd_iat_mean()     const noexcept { return fwd_iat.safe_mean();  }

    // [24] Flow IAT Max
    double flow_iat_max()     const noexcept { return flow_iat.safe_max();  }

    // [26] Fwd IAT Max
    double fwd_iat_max()      const noexcept { return fwd_iat.safe_max();   }

    // [32] Bwd IAT Total
    uint64_t bwd_iat_total_val() const noexcept { return bwd_iat_total;     }

    // [34] Fwd IAT Min
    double fwd_iat_min()      const noexcept { return fwd_iat.safe_min();   }

    // Not in top 38 but tracked for free — may be useful later
    double flow_iat_mean()    const noexcept { return flow_iat.safe_mean(); }
    double flow_iat_std()     const noexcept { return flow_iat.stddev();    }
    double flow_iat_min()     const noexcept { return flow_iat.safe_min();  }
    double fwd_iat_std()      const noexcept { return fwd_iat.stddev();     }
    uint64_t fwd_iat_total_val() const noexcept { return fwd_iat_total;     }
    double bwd_iat_mean()     const noexcept { return bwd_iat.safe_mean();  }
    double bwd_iat_std()      const noexcept { return bwd_iat.stddev();     }
    double bwd_iat_max()      const noexcept { return bwd_iat.safe_max();   }
    double bwd_iat_min()      const noexcept { return bwd_iat.safe_min();   }
};