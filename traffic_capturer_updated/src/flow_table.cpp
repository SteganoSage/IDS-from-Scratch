#include "FlowTable.hpp"

// ---------------------------------------------------------------------------
// FlowTable implementation
//
// Key design decisions:
//   - flows_.reserve(65536) up front: avoids rehashing during the initial
//     burst of new flows, which would invalidate iterators mid-iteration.
//   - try_emplace: atomically looks up or constructs the Flow under the same
//     lock, eliminating the dangling-reference bug of returning a Flow& after
//     unlock.
//   - update_flow() takes PacketMeta instead of the old boolean explosion.
//     All six stat modules get exactly what they need from one struct.
//   - expire_idle_flows() must NOT be called on every packet — O(n) scan.
//     Worker throttles calls to once per 1 000 packets.
// ---------------------------------------------------------------------------

FlowTable::FlowTable(uint64_t idle_timeout_us)
    : idle_timeout_us_(idle_timeout_us)
{
    flows_.reserve(65536);
}

void FlowTable::update_flow(const FlowKey &key, const PacketMeta &meta)
{
    std::lock_guard<std::mutex> lock(mtx_);

    // try_emplace: if key exists, returns the existing entry without
    // constructing a new Flow. If new, constructs Flow(key, meta.ts_us).
    // Both lookup and update happen inside the same lock.
    auto [it, inserted] = flows_.try_emplace(key, key, meta.ts_us, meta.wall_ts_us);
    it->second.update(meta);
}

std::vector<Flow> FlowTable::expire_idle_flows(uint64_t current_ts_us)
{
    std::vector<Flow> expired;
    std::lock_guard<std::mutex> lock(mtx_);

    for (auto it = flows_.begin(); it != flows_.end(); ) {
        // Guard against timestamp weirdness on loopback (last_seen > current)
        const uint64_t idle = (current_ts_us > it->second.last_seen_ts_us)
                              ? current_ts_us - it->second.last_seen_ts_us
                              : 0;
        if (idle >= idle_timeout_us_) {
            expired.push_back(std::move(it->second));
            it = flows_.erase(it);
        } else {
            ++it;
        }
    }
    return expired;
}

size_t FlowTable::active_flow_count() const
{
    std::lock_guard<std::mutex> lock(mtx_);
    return flows_.size();
}