#pragma once
#include <cstdint>
#include <limits>

// ---------------------------------------------------------------------------
// TCPStats — O(1) TCP-specific statistics.
//
// TCP flags byte layout (RFC 793 + extensions):
//   bit 0 = FIN  0x01
//   bit 1 = SYN  0x02
//   bit 2 = RST  0x04
//   bit 3 = PSH  0x08
//   bit 4 = ACK  0x10
//   bit 5 = URG  0x20
//   bit 6 = ECE  0x40
//   bit 7 = CWR  0x80
// ---------------------------------------------------------------------------
struct TCPStats {

    // ── Flag counts (all directions unless noted) ─────────────────────────
    uint32_t psh_count{0};      // PSH Flag Cnt
    uint32_t ack_count{0};      // ACK Flag Cnt
    uint32_t syn_count{0};      // SYN Flag Cnt
    uint32_t fin_count{0};      // FIN Flag Cnt
    uint32_t urg_count{0};      // URG Flag Cnt
    uint32_t rst_count{0};      // RST Flag Cnt
    uint32_t ece_count{0};      // ECE Flag Cnt  (bit 0x40)
    uint32_t fwd_psh_count{0};  // Fwd PSH Flags (forward only)
    uint32_t fwd_urg_count{0};  // Fwd URG Flags (forward only)

    // ── Init window bytes ─────────────────────────────────────────────────
    uint16_t init_win_fwd{0};
    uint16_t init_win_bwd{0};
    bool     fwd_win_set{false};
    bool     bwd_win_set{false};

    // ── min_seg_size_forward (Fwd Seg Size Min) ───────────────────────────
    uint16_t min_seg_size_fwd{std::numeric_limits<uint16_t>::max()};
    bool     fwd_tcp_seen{false};

    // ── act_data_pkt_fwd (Fwd Act Data Pkts) ─────────────────────────────
    uint32_t act_data_pkt_fwd{0};

    // Update — O(1), called for every packet
    inline void update(uint8_t  tcp_flags,
                       uint16_t tcp_window,
                       uint16_t tcp_header_len,
                       uint32_t payload_len,
                       bool     forward) noexcept
    {
        // ── Flag counts ───────────────────────────────────────────────────
        if (tcp_flags & 0x08) { psh_count++; if (forward) fwd_psh_count++; }
        if (tcp_flags & 0x10)   ack_count++;
        if (tcp_flags & 0x02)   syn_count++;
        if (tcp_flags & 0x01)   fin_count++;
        if (tcp_flags & 0x20) { urg_count++; if (forward) fwd_urg_count++; }
        if (tcp_flags & 0x04)   rst_count++;
        if (tcp_flags & 0x40)   ece_count++;

        // ── Init window — captured once per direction ─────────────────────
        if (forward && !fwd_win_set) { init_win_fwd = tcp_window; fwd_win_set = true; }
        else if (!forward && !bwd_win_set) { init_win_bwd = tcp_window; bwd_win_set = true; }

        // ── min_seg_size_forward ──────────────────────────────────────────
        if (forward) {
            fwd_tcp_seen = true;
            if (tcp_header_len < min_seg_size_fwd)
                min_seg_size_fwd = tcp_header_len;
        }

        // ── act_data_pkt_fwd ─────────────────────────────────────────────
        if (forward && payload_len > 0)
            act_data_pkt_fwd++;
    }

    // ── Feature accessors ─────────────────────────────────────────────────
    uint16_t init_win_bytes_forward()   const noexcept { return init_win_fwd;      }
    uint16_t init_win_bytes_backward()  const noexcept { return init_win_bwd;      }
    uint32_t psh_flag_count()           const noexcept { return psh_count;         }
    uint32_t ack_flag_count()           const noexcept { return ack_count;         }
    uint32_t syn_flag_count()           const noexcept { return syn_count;         }
    uint32_t fin_flag_count()           const noexcept { return fin_count;         }
    uint32_t urg_flag_count()           const noexcept { return urg_count;         }
    uint32_t rst_flag_count()           const noexcept { return rst_count;         }
    uint32_t ece_flag_count()           const noexcept { return ece_count;         }
    uint32_t fwd_psh_flags()            const noexcept { return fwd_psh_count;     }
    uint32_t fwd_urg_flags()            const noexcept { return fwd_urg_count;     }
    uint32_t act_data_pkts_fwd()        const noexcept { return act_data_pkt_fwd;  }
    uint16_t min_seg_size_forward()     const noexcept {
        return fwd_tcp_seen ? min_seg_size_fwd : 0;
    }
};