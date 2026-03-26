#pragma once

#include "Flow.hpp"
#include "PacketMeta.hpp"
#include <unordered_map>
#include <vector>
#include <mutex>
#include <cstdint>

// ---------------------------------------------------------------------------
// FlowTable — thread-safe map of FlowKey → Flow.
//
// Interface change from the old version:
//   OLD: update_flow(key, ts_us, pkt_len, forward, syn, ack, fin, rst, psh)
//   NEW: update_flow(key, meta)
//
// Rationale: PacketMeta now carries every field that all six stat modules
// need (ip_total_len, ip_header_len, tcp_header_len, tcp_window,
// payload_len, tcp_flags, forward, ts_us).  Adding a new stat module
// never requires a signature change here.
//
// Thread safety:
//   update_flow() — acquires the mutex for the full create-or-update.
//   expire_idle_flows() — acquires the mutex; do NOT call on every packet.
//   active_flow_count() — acquires the mutex (shared/const).
//
// expire_idle_flows() returns expired Flow objects by value so the caller
// can run FeatureExtractor on them outside the lock.
// ---------------------------------------------------------------------------
class FlowTable {
public:
    // idle_timeout_us: flow is expired if (now - last_seen) >= this value.
    // Typical CICFlowMeter value: 120,000,000 µs (120 seconds).
    explicit FlowTable(uint64_t idle_timeout_us);

    // Create-or-update a flow atomically under one lock.
    // meta.forward must already be resolved by the Worker before calling.
    void update_flow(const FlowKey &key, const PacketMeta &meta);

    // Scan all flows; remove and return any whose last_seen_ts_us is older
    // than (current_ts_us - idle_timeout_us_).
    // Call periodically (e.g. every 1 000 packets), NOT on every packet.
    std::vector<Flow> expire_idle_flows(uint64_t current_ts_us);

    // Returns the number of currently active (non-expired) flows.
    size_t active_flow_count() const;

private:
    std::unordered_map<FlowKey, Flow, FlowKeyHash> flows_;
    uint64_t           idle_timeout_us_;
    mutable std::mutex mtx_;
};