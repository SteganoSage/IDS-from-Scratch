#pragma once
#include "Packet.hpp"
#include <deque>
#include <mutex>
#include <condition_variable>
#include <atomic>

class ThreadSafeQueue {
public:
    ThreadSafeQueue();
    ~ThreadSafeQueue();

    void push(Packet &&p);
    bool pop(Packet &out); // blocked until item or closed; returns false if closed & empty
    void close();
    bool empty() const;
private:
    std::deque<Packet> q_;
    mutable std::mutex mtx_;
    std::condition_variable cv_;
    std::atomic<bool> closed_;
};
