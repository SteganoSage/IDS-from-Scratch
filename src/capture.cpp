#include "Capture.hpp"
#include "Packet.hpp"
#include <iostream>
#include <cstring>

// callback must be extern "C"
extern "C" void capture_callback(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes) {
    if (!user || !h || !bytes) return;
    ThreadSafeQueue* q = reinterpret_cast<ThreadSafeQueue*>(user);
    Packet p(h->ts, h->caplen, h->len, bytes);
    q->push(std::move(p));
}

CaptureEngine::CaptureEngine(): handle_(nullptr) {}
CaptureEngine::~CaptureEngine() { close(); }

bool CaptureEngine::open_live(const std::string &dev, int snaplen, bool promisc, int to_ms, std::string *err) {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle_ = pcap_open_live(dev.c_str(), snaplen, promisc ? 1 : 0, to_ms, errbuf);
    if (!handle_) {
        if (err) *err = errbuf;
        return false;
    }
    return true;
}

int CaptureEngine::loop(int cnt, ThreadSafeQueue *out_queue) {
    if (!handle_) return -1;
    return pcap_loop(handle_, cnt, capture_callback, reinterpret_cast<u_char*>(out_queue));
}

void CaptureEngine::break_loop() {
    if (handle_) pcap_breakloop(handle_);
}

void CaptureEngine::close() {
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}
