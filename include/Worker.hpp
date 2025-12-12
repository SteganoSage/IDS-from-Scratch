#pragma once
#include "Queue.hpp"
#include "Packet_Parser.hpp"
#include <atomic>
#include "Rules.hpp"

class Worker {
public:
    Worker(ThreadSafeQueue &q, int id, std::atomic<bool> &running_flag, const std::vector<Rule>& rules);
    void operator()();

private:
    ThreadSafeQueue &queue_;
    int id_;
    std::atomic<bool> &running_;

    const std::vector<Rule>& rules_;
};
