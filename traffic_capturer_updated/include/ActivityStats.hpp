#pragma once
#include "RunningStats.hpp"
#include <cstdint>

// ---------------------------------------------------------------------------
// ActivityStats — O(1) active/idle burst detection.
//
// CICFlowMeter definition:
//   A "gap" between consecutive packets is classified as:
//     IDLE   if gap >= IDLE_THRESHOLD_US  (1,000,000 µs = 1 second)
//     ACTIVE if gap <  IDLE_THRESHOLD_US
//
//   An "active period" is a run of packets with no idle gap.
//   When an idle gap is detected:
//     1. Record the duration of the just-ended active period → active_stats
//     2. Record the idle gap itself                          → idle_stats
//     3. Start a new active period from the next packet
//
//   The very first packet starts the first active period.
//   The last active period (at flow expiry) is finalized in finish().
//
// Top-38 feature from this module:
//   [33] Idle Max  →  idle_stats.safe_max()
//
// Full set tracked (costs nothing extra):
//   Active Mean/Std/Max/Min, Idle Mean/Std/Max/Min
// ---------------------------------------------------------------------------
struct ActivityStats {

    // 1 second in microseconds — CICFlowMeter hardcoded threshold
    static constexpr uint64_t IDLE_THRESHOLD_US = 1'000'000;

    RunningStats active_stats;      // duration of each active burst (µs)
    RunningStats idle_stats;        // duration of each idle gap (µs)

    uint64_t current_active_start{0};  // start of the current active burst
    uint64_t last_pkt_ts{0};           // timestamp of last packet seen
    bool     first_pkt_seen{false};    // guard for first packet

    // Update — called for every packet in timestamp order, O(1)
    inline void update(uint64_t ts_us) noexcept {
        if (!first_pkt_seen) {
            // First packet: begin the first active period
            current_active_start = ts_us;
            last_pkt_ts          = ts_us;
            first_pkt_seen       = true;
            return;
        }

        // Guard against out-of-order timestamps
        uint64_t gap = (ts_us >= last_pkt_ts)
                       ? ts_us - last_pkt_ts
                       : 0;

        if (gap >= IDLE_THRESHOLD_US) {
            // ── Idle gap detected ─────────────────────────────────────────
            // 1. Finalize the active period that just ended
            uint64_t active_dur = last_pkt_ts - current_active_start;
            active_stats.update(static_cast<double>(active_dur));

            // 2. Record the idle gap
            idle_stats.update(static_cast<double>(gap));

            // 3. Start a new active period from this packet
            current_active_start = ts_us;
        }
        // else: gap < threshold → still in the same active period, nothing to record

        last_pkt_ts = ts_us;
    }

    // finish() — call once when the flow expires.
    // Finalizes the last active period (from current_active_start → last_pkt_ts).
    // Must be called before reading active_stats accessors for accurate results.
    inline void finish() noexcept {
        if (!first_pkt_seen) return;
        // Guard against loopback timestamp reversals
        uint64_t final_active = (last_pkt_ts > current_active_start)
                                ? last_pkt_ts - current_active_start
                                : 0;
        active_stats.update(static_cast<double>(final_active));
    }

    // ── Feature accessors ─────────────────────────────────────────────────

    // [33] Idle Max  ← only top-38 feature from this module
    double idle_max()    const noexcept { return idle_stats.safe_max();  }

    // Full idle set (tracked for free)
    double idle_mean()   const noexcept { return idle_stats.safe_mean(); }
    double idle_min()    const noexcept { return idle_stats.safe_min();  }
    double idle_std()    const noexcept { return idle_stats.stddev();    }

    // Full active set (tracked for free)
    double active_mean() const noexcept { return active_stats.safe_mean(); }
    double active_min()  const noexcept { return active_stats.safe_min();  }
    double active_max()  const noexcept { return active_stats.safe_max();  }
    double active_std()  const noexcept { return active_stats.stddev();    }
};