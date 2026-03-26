#pragma once
#include "Packet.hpp"
#include <deque>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <cstdint>

class ThreadSafeQueue {
public:
    static constexpr size_t MAX_SIZE = 65536;

    ThreadSafeQueue();
    ~ThreadSafeQueue();

    // Returns true if pushed, false if dropped (queue full)
    bool push(Packet &&p);

    // Blocks until item available or closed. Returns false if closed & empty.
    bool pop(Packet &out);

    void close();
    bool empty() const;

    uint64_t dropped_count() const { return dropped_count_.load(); }

private:
    std::deque<Packet>      q_;
    mutable std::mutex      mtx_;
    std::condition_variable cv_;
    std::atomic<bool>       closed_;
    std::atomic<uint64_t>   dropped_count_;
};