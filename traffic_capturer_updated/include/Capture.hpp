#pragma once
#include "Queue.hpp"
#include <string>
#include <pcap.h>

class CaptureEngine {
public:
    CaptureEngine();
    ~CaptureEngine();

    bool open_live(const std::string &dev,
                   int snaplen   = 65535,
                   bool promisc  = true,
                   int to_ms     = 1000,
                   std::string *err = nullptr);

    // Apply a BPF filter string, e.g. "ip and (tcp or udp)"
    // Must be called after open_live().
    bool set_filter(const std::string &filter_expr);

    // Returns the datalink type (DLT_EN10MB=1, DLT_LINUX_SLL=113, etc.)
    // Must be called after open_live().
    int datalink() const;

    // Returns the last pcap error string (safe — never passes nullptr).
    std::string get_error() const;

    // Blocks until cnt packets captured or break_loop() called.
    int loop(int cnt, ThreadSafeQueue *out_queue);

    void break_loop();
    void close();

private:
    pcap_t *handle_;
};