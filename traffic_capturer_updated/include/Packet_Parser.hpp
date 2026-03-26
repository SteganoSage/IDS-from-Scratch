#pragma once
#include "Packet.hpp"
#include "Headers.hpp"
#include "PacketMeta.hpp"
#include <cstdint>

// ---------------------------------------------------------------------------
// ParsedPacket — result of parsing one raw packet.
//
// Stores everything the Worker needs to:
//   1. Build a FlowKey
//   2. Fill a PacketMeta
//
// Design rules:
//   - All fields are plain numeric (uint32_t IPs, not strings)
//   - ip_total_len  = ip->ntoh_total_length()  (NOT caplen — CIC uses this)
//   - tcp_window    = ntohs(tcp->window)        (for Init_Win features)
//   - payload_len   = actual L7 bytes           (for act_data_pkt_fwd)
//   - Struct is reused across loop iterations via reset()
// ---------------------------------------------------------------------------
struct ParsedPacket {
    // ── Ethernet ──────────────────────────────────────────────────────────
    uint16_t ethertype{0};

    // ── IP ────────────────────────────────────────────────────────────────
    bool     is_ipv4{false};
    uint32_t src_ip{0};           // host byte order
    uint32_t dst_ip{0};           // host byte order
    uint8_t  ip_proto{0};
    uint16_t ip_header_len{0};    // bytes (min 20)
    uint16_t ip_total_len{0};     // from IP header — used for all length features

    bool     is_fragment{false};

    // ── Transport ─────────────────────────────────────────────────────────
    bool     is_tcp{false};
    bool     is_udp{false};
    bool     is_icmp{false};
    bool     is_other_l4{false};

    bool     has_ports{false};
    uint16_t src_port{0};
    uint16_t dst_port{0};
    uint16_t tcp_header_len{0};   // bytes (min 20 for TCP, 0 for UDP/ICMP)
    uint16_t tcp_window{0};       // raw TCP window size (host order), 0 if not TCP
    uint8_t  tcp_flags{0};        // raw flags byte, 0 if not TCP

    // ── Payload ───────────────────────────────────────────────────────────
    // Points into the Packet buffer — zero-copy.
    // payload_len = ip_total_len - ip_header_len - tcp/udp_header_len
    // (this is the correct L7 length, not caplen-based)
    const uint8_t *payload{nullptr};
    uint32_t       payload_len{0};

    // Reset for reuse across loop iterations — no per-packet stack alloc
    inline void reset() noexcept { *this = ParsedPacket{}; }

    // ── Convenience: build PacketMeta for FlowTable ────────────────────
    // Call after parse_packet() succeeds and forward direction is known.
    inline PacketMeta to_meta(uint64_t pcap_ts_us, uint64_t wall_ts_us, bool fwd) const noexcept {
        return PacketMeta{
            pcap_ts_us,
            wall_ts_us,
            ip_total_len,
            ip_header_len,
            tcp_header_len,
            tcp_window,
            payload_len,
            tcp_flags,
            fwd
        };
    }
};

// ---------------------------------------------------------------------------
// parse_packet — fills 'out' in place, returns false if packet is unusable.
// 'out' is caller-owned and reused across iterations (no allocation).
// ---------------------------------------------------------------------------
// datalink: DLT_EN10MB (1) for Ethernet, DLT_LINUX_SLL (113) for Docker/cooked.
bool parse_packet(const Packet &pkt, ParsedPacket &out, int datalink = 1) noexcept;