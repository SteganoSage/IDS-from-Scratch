#include "Capture.hpp"
#include "Packet.hpp"
#include <iostream>

// pcap callback: must be a plain C function
extern "C" void capture_callback(u_char *user,
                                  const struct pcap_pkthdr *h,
                                  const u_char *bytes)
{
    if (!user || !h || !bytes) return;
    auto *q = reinterpret_cast<ThreadSafeQueue *>(user);
    Packet p(h->ts, h->caplen, h->len, bytes);
    if (!q->push(std::move(p))) {
        // Queue full — packet silently dropped (counted by queue).
        // Could log here if desired, but avoid noisy stdout in hot path.
    }
}

CaptureEngine::CaptureEngine() : handle_(nullptr) {}
CaptureEngine::~CaptureEngine() { close(); }

bool CaptureEngine::open_live(const std::string &dev,
                               int snaplen, bool promisc,
                               int to_ms, std::string *err)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    handle_ = pcap_open_live(dev.c_str(), snaplen,
                              promisc ? 1 : 0, to_ms, errbuf);
    if (!handle_) {
        if (err) *err = errbuf;
        return false;
    }
    return true;
}

int CaptureEngine::datalink() const
{
    if (!handle_) return -1;
    return pcap_datalink(handle_);
}

bool CaptureEngine::set_filter(const std::string &filter_expr)
{
    if (!handle_) return false;
    struct bpf_program fp;
    if (pcap_compile(handle_, &fp, filter_expr.c_str(),
                     1, PCAP_NETMASK_UNKNOWN) == -1) {
        return false;
    }
    bool ok = (pcap_setfilter(handle_, &fp) == 0);
    pcap_freecode(&fp);
    return ok;
}

std::string CaptureEngine::get_error() const
{
    if (!handle_) return "no pcap handle";
    return pcap_geterr(handle_);  // safe — handle is valid
}

int CaptureEngine::loop(int cnt, ThreadSafeQueue *out_queue)
{
    if (!handle_) return -1;
    return pcap_loop(handle_, cnt, capture_callback,
                     reinterpret_cast<u_char *>(out_queue));
}

void CaptureEngine::break_loop()
{
    if (handle_) pcap_breakloop(handle_);
}

void CaptureEngine::close()
{
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}