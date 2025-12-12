#include "Queue.hpp"

ThreadSafeQueue::ThreadSafeQueue(): closed_(false) {}

ThreadSafeQueue::~ThreadSafeQueue() {
    close();
}

void ThreadSafeQueue::push(Packet &&p) {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        q_.push_back(std::move(p));
    }
    cv_.notify_one();
}

bool ThreadSafeQueue::pop(Packet &out) {
    std::unique_lock<std::mutex> lk(mtx_);
    cv_.wait(lk, [&]{ return !q_.empty() || closed_.load(); });
    if (q_.empty()) return false;
    out = std::move(q_.front());
    q_.pop_front();
    return true;
}

void ThreadSafeQueue::close() {
    closed_.store(true);
    cv_.notify_all();
}

bool ThreadSafeQueue::empty() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return q_.empty();
}
