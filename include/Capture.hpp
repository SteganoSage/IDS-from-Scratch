#pragma once
#include "Queue.hpp"
#include <string>
#include <pcap.h>

class CaptureEngine {
public:
    CaptureEngine();
    ~CaptureEngine();

    bool open_live(const std::string &dev, int snaplen = 65535, bool promisc = true, int to_ms = 1000, std::string *err = nullptr);
    int loop(int cnt, ThreadSafeQueue *out_queue); // blocks, returns pcap_loop return
    void break_loop();
    void close();

private:
    pcap_t* handle_;
};
