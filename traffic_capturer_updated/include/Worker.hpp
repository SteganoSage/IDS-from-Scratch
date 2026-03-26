#pragma once
#include "Queue.hpp"
#include "FlowTable.hpp"
#include "Flow.hpp"
#include <atomic>
#include <cstdint>
#include <vector>
#include <chrono>
#include <thread>

class Worker {
public:
    Worker(ThreadSafeQueue &q, int id,
           std::atomic<bool> &running_flag,
           FlowTable &flow_table);

    void operator()();

    // Public so main() can call it for the final drain on PCAP EOF.
    // Non-const ref because FeatureExtractor::extract() mutates the flow
    // (calls activity.finish()).
    void print_expired(std::vector<Flow> &expired);

    // Returns current wall-clock time in microseconds.
    // Used for the wall-clock expiry trigger (Trigger 2 in worker.cpp).
    static inline uint64_t wall_clock_us() noexcept {
        using namespace std::chrono;
        return static_cast<uint64_t>(
            duration_cast<microseconds>(
                steady_clock::now().time_since_epoch()
            ).count()
        );
    }

private:
    ThreadSafeQueue   &queue_;
    int                id_;
    std::atomic<bool> &running_;
    FlowTable         &flow_table_;
    uint64_t           packet_count_{0};
};


// ---------------------------------------------------------------------------
// ExpiryThread — dedicated background thread that scans for idle flows
// on a fixed wall-clock interval, completely independent of packet rate.
//
// This is the correct solution for the port-scan case:
//   - nmap fires 10 000 SYNs in ~100ms
//   - All flows are created instantly, then nothing arrives
//   - packet_count_ never advances past the burst
//   - Without ExpiryThread, flows sit until the next burst or Ctrl+C
//
// Usage in main():
//   ExpiryThread expiry(flow_table, g_running, workers[0], interval_ms);
//   std::thread expiry_thread(std::ref(expiry));
//   // ... capture loop ...
//   expiry_thread.join();
// ---------------------------------------------------------------------------
class ExpiryThread {
public:
    // interval_ms: how often to scan for idle flows (default: 5 000ms = 5s)
    // Use a value slightly less than your --timeout so flows expire promptly.
    ExpiryThread(FlowTable        &flow_table,
                 std::atomic<bool> &running,
                 Worker            &worker,
                 uint64_t           interval_ms = 5'000)
        : flow_table_(flow_table)
        , running_(running)
        , worker_(worker)
        , interval_ms_(interval_ms)
    {}

    void operator()() {
        using namespace std::chrono_literals;
        while (running_.load()) {
            // Sleep in small increments so we wake up promptly on shutdown
            for (uint64_t i = 0; i < interval_ms_ && running_.load(); ++i)
                std::this_thread::sleep_for(1ms);

            if (!running_.load()) break;

            uint64_t now_us = Worker::wall_clock_us();
            std::vector<Flow> expired = flow_table_.expire_idle_flows(now_us);
            if (!expired.empty()) {
                worker_.print_expired(expired);
            }
        }
    }

private:
    FlowTable         &flow_table_;
    std::atomic<bool> &running_;
    Worker            &worker_;
    uint64_t           interval_ms_;
};