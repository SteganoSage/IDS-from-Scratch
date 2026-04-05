#pragma once

#include <cstdint>
#include <limits>
#include <functional>
#include <cmath>

#include "LengthStats.hpp"
#include "IATStats.hpp"
#include "ActivityStats.hpp"
#include "HeaderStats.hpp"
#include "TCPStats.hpp"
#include "VolumeStats.hpp"
#include "PacketMeta.hpp"

// ---------------------------------------------------------------------------
// FlowKey — 5-tuple in host byte order.
// uint32_t IPs are far cheaper to hash/compare than strings.
// ---------------------------------------------------------------------------
struct FlowKey {
    uint32_t src_ip{0};
    uint32_t dst_ip{0};
    uint16_t src_port{0};
    uint16_t dst_port{0};
    uint8_t  protocol{0};

    FlowKey() = default;
    FlowKey(uint32_t s_ip, uint32_t d_ip,
            uint16_t s_port, uint16_t d_port, uint8_t proto)
        : src_ip(s_ip), dst_ip(d_ip),
          src_port(s_port), dst_port(d_port), protocol(proto) {}

    bool operator==(const FlowKey &o) const noexcept {
        return src_ip   == o.src_ip   &&
               dst_ip   == o.dst_ip   &&
               src_port == o.src_port &&
               dst_port == o.dst_port &&
               protocol == o.protocol;
    }
};

// ---------------------------------------------------------------------------
// FlowKeyHash — murmur-inspired mixing.
// Avoids trivially-colliding XOR-shift patterns.
// ---------------------------------------------------------------------------
struct FlowKeyHash {
    std::size_t operator()(const FlowKey &k) const noexcept {
        uint64_t a = (uint64_t)k.src_ip << 32 | k.dst_ip;
        uint64_t b = (uint64_t)k.src_port << 32 |
                     (uint64_t)k.dst_port << 16 |
                     (uint64_t)k.protocol;
        a ^= a >> 33; a *= 0xff51afd7ed558ccdULL; a ^= a >> 33;
        b ^= b >> 33; b *= 0xc4ceb9fe1a85ec53ULL; b ^= b >> 33;
        return static_cast<std::size_t>(a ^ b);
    }
};

// ---------------------------------------------------------------------------
// Flow — one live flow record.
//
// All statistics are fully delegated to the purpose-built stat modules.
// The old hand-rolled Welford / flag fields are gone — the modules are
// now the single source of truth.
//
// Data-flow per packet:
//   Worker builds PacketMeta from ParsedPacket
//   → FlowTable::update_flow(key, meta)
//       → Flow::update(meta)
//           → length.update(meta.ip_total_len, meta.forward)
//           → iat.update(meta.ts_us, meta.forward)
//           → activity.update(meta.ts_us)
//           → headers.update(meta.ip_header_len, meta.tcp_header_len, meta.forward)
//           → tcp.update(...)    [TCP only]
//           → volume.update(meta.forward)
//
// At flow expiry:
//   activity.finish() must be called before reading active/idle features.
//   FeatureExtractor::extract() calls finish() internally.
// ---------------------------------------------------------------------------
struct Flow {

    // ── Identity ─────────────────────────────────────────────────────────
    FlowKey  key;
    uint64_t start_ts_us{0};          // pcap time of first packet — for duration
    uint64_t last_seen_ts_us{0};      // wall clock of last packet — for expiry only
    uint64_t last_pcap_ts_us{0};       // pcap time of last packet — for duration

    // ── Stat modules (one per feature domain) ────────────────────────────
    LengthStats   length;    // packet lengths  (ip_total_len)
    IATStats      iat;       // inter-arrival times
    ActivityStats activity;  // active/idle bursts
    HeaderStats   headers;   // header byte totals (fwd/bwd)
    TCPStats      tcp;       // flags, init windows, min_seg, act_data
    VolumeStats   volume;    // packet/flow counts

    // ── Convenience counters needed by FeatureExtractor ──────────────────
    // total_bytes is needed for Average Packet Size computation.
    // VolumeStats tracks counts; lengths are in LengthStats.
    // total_bytes = length.fwd_total_bytes + length.bwd_total_bytes — use that.

    // ── Constructors ─────────────────────────────────────────────────────
    Flow() = default;
    Flow(const FlowKey &k, uint64_t pcap_ts_us, uint64_t wall_ts_us)
        : key(k),
          start_ts_us(pcap_ts_us),
          last_seen_ts_us(wall_ts_us),
          last_pcap_ts_us(pcap_ts_us) {}   // ← initialize to first packet time

    // ── Main update — called once per packet ─────────────────────────────
    // PacketMeta carries every field all six modules need.
    // tcp.update() is only called when meta.tcp_flags != 0 OR protocol==6;
    // caller (FlowTable) is responsible for only routing TCP meta here,
    // but it's safe to call for UDP/ICMP too — TCPStats guards with
    // zero-initialised fields and protocol flag in meta is implicit.
    void update(const PacketMeta &meta) noexcept
    {
        last_seen_ts_us = meta.wall_ts_us;   // wall clock — expiry only
        last_pcap_ts_us  = meta.ts_us;         // pcap time  — duration

        // Delegate to every module — each is O(1), no allocation
        // FIX: Pass all header lengths so LengthStats computes payload-only
        // lengths matching CICFlowMeter semantics.
        length.update(meta.ip_total_len, meta.ip_header_len,
                      meta.tcp_header_len, meta.forward);
        iat.update(meta.ts_us, meta.forward);     // pcap time — real wire IAT
        activity.update(meta.ts_us);              // pcap time — real active/idle
        headers.update(meta.ip_header_len, meta.tcp_header_len, meta.forward);
        volume.update(meta.forward);

        // tcp_flags == 0 AND tcp_header_len == 0 → UDP/ICMP packet.
        // TCPStats.update() is still called: for UDP/ICMP tcp_flags==0 so
        // no flag counters change; init windows / min_seg stay at defaults.
        // This avoids a branch here at the cost of one no-op update, which
        // is cheaper than a mis-predict on every TCP packet.
        tcp.update(meta.tcp_flags,
                   meta.tcp_window,
                   meta.tcp_header_len,
                   meta.payload_len,
                   meta.forward);
    }

    // ── Duration helper ───────────────────────────────────────────────────
    uint64_t duration_us() const noexcept {
        // Guard against loopback timestamp reversals (same-microsecond packets)
        return (last_pcap_ts_us > start_ts_us)
               ? last_pcap_ts_us - start_ts_us
               : 0;
    }

    // ── Total bytes (needed for Avg Packet Size in FeatureExtractor) ─────
    uint64_t total_bytes() const noexcept {
        return length.fwd_total_bytes + length.bwd_total_bytes;
    }
};