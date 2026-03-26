#pragma once
#include <cstdint>

// ---------------------------------------------------------------------------
// PacketMeta — compact per-packet data passed from Worker → FlowTable.
//
// Filled by the worker from ParsedPacket + Packet.
// Keeps FlowTable::update_flow() signature clean as features grow.
// All fields are plain numeric — zero strings, zero allocation.
// ---------------------------------------------------------------------------
struct PacketMeta {
    uint64_t ts_us;           // pcap timestamp in microseconds — used for ALL flow features
    uint64_t wall_ts_us;      // steady_clock wall time — used ONLY for idle expiry
    uint16_t ip_total_len;    // from ip->ntoh_total_length() — NOT caplen
    uint16_t ip_header_len;   // from ip->header_length_bytes()
    uint16_t tcp_header_len;  // from tcp->header_length_bytes(); 0 if not TCP
    uint16_t tcp_window;      // from ntohs(tcp->window);         0 if not TCP
    uint32_t payload_len;     // actual L7 payload bytes (ip_total_len - ip_hdr - l4_hdr)
    uint8_t  tcp_flags;       // raw TCP flags byte;              0 if not TCP
    bool     forward;         // true = same direction as flow key's src→dst
};