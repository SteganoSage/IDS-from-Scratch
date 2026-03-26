#include <iostream>
#include<pcap.h>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <atomic>
#include <cstring>
#include <csignal>
#include <sstream>
#include <iomanip>
#include "Headers.hpp"

struct Packet {
    timeval ts;
    uint32_t caplen;
    uint32_t len;
    std::vector<uint8_t> data;
};

class ThreadSafeQueue {
    std::deque<Packet> q; std::mutex m; std::condition_variable cv; bool closed=false;
public:
    void push(Packet &&p) { { std::lock_guard<std::mutex> lk(m); q.push_back(std::move(p)); } cv.notify_one(); }
    bool pop(Packet &out) {
        std::unique_lock<std::mutex> lk(m);
        cv.wait(lk, [&]{ return !q.empty() || closed; });
        if (q.empty()) return false;
        out = std::move(q.front()); q.pop_front(); return true;
    }
    void close() { { std::lock_guard<std::mutex> lk(m); closed=true; } cv.notify_all(); }
};

static pcap_t* g_handle = nullptr;
static std::atomic<bool> g_running{true};

void parse_and_print(const Packet& pkt) {
    const uint8_t* raw = pkt.data.data();
    std::size_t caplen = pkt.caplen;

    
    if (caplen < sizeof(EthernetHeader)) return;

    const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(raw);
    uint16_t ethertype = eth->ntoh_ethertype();

    std::cout << "Ethernet: src=" << format_mac(eth->src_mac)
              << " dst=" << format_mac(eth->dest_mac)
              << " type=0x" << std::hex << ethertype << std::dec << "\n";

    
    if (ethertype != 0x0800) return;

   
    std::size_t ip_offset = sizeof(EthernetHeader);
    if (caplen < ip_offset + sizeof(IPv4Header)) return; // ensure at least minimal IPv4 available

    const IPv4Header* ip = reinterpret_cast<const IPv4Header*>(raw + ip_offset);
    // Now we must ensure the full IP header (including options) is within caplen
    std::size_t ip_header_len = ip->header_length_bytes();
    if (ip_header_len < 20) return; // invalid IHL
    if (caplen < ip_offset + ip_header_len) return; // truncated IP header

    uint32_t src_ip = ip->ntoh_src_addr();
    uint32_t dst_ip = ip->ntoh_dst_addr();

    std::cout << "IPv4: src=" << format_ipv4(src_ip)
              << " dst=" << format_ipv4(dst_ip)
              << " proto=" << int(ip->protocol)
              << " ihl=" << ip_header_len << "\n";

    
    std::size_t l4_offset = ip_offset + ip_header_len;
    if (ip->protocol == 6) { // TCP
        if (caplen < l4_offset + sizeof(TCPHeader)) return; // minimal TCP header
        const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(raw + l4_offset);
        std::size_t tcp_hdr_len = tcp->header_length_bytes();
        if (tcp_hdr_len < 20) return; // invalid data offset
        if (caplen < l4_offset + tcp_hdr_len) return; // truncated TCP header

        uint16_t sport = tcp->ntoh_src_port();
        uint16_t dport = tcp->ntoh_dst_port();

        std::cout << "TCP: sport=" << sport << " dport=" << dport
                  << " flags=" << std::hex << int(tcp->flags) << std::dec
                  << " hdr_len=" << tcp_hdr_len << "\n";

        // payload start:
        std::size_t payload_offset = l4_offset + tcp_hdr_len;
        if (payload_offset < caplen) {
            std::size_t payload_len = caplen - payload_offset;
            std::cout << "Payload length: " << payload_len << "\n";
            // you can inspect bytes: raw + payload_offset, length payload_len
        }
    } else if (ip->protocol == 17) { // UDP
        if (caplen < l4_offset + sizeof(UDPHeader)) return;
        const UDPHeader* udp = reinterpret_cast<const UDPHeader*>(raw + l4_offset);
        uint16_t sport = udp->ntoh_src_port();
        uint16_t dport = udp->ntoh_dst_port();
        uint16_t udplen = udp->ntoh_length();
        std::cout << "UDP: sport=" << sport << " dport=" << dport << " len=" << udplen << "\n";
        std::size_t payload_offset = l4_offset + sizeof(UDPHeader);
        if (payload_offset < caplen) {
            std::size_t payload_len = caplen - payload_offset;
            std::cout << "Payload len: " << payload_len << "\n";
        }
    } else {
        // other protocols (ICMP etc.)
    }
}

extern "C" void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* bytes){
	if (!user || !header || !bytes) return;;

	std::cout << "Packet_len : "<< header->len << std :: endl << "Caplen : "<< header->caplen << std::endl<< "ts : " << header->ts.tv_sec << "." << header->ts.tv_usec << "\n";

	ThreadSafeQueue* q = reinterpret_cast<ThreadSafeQueue*>(user);
    Packet p;
    p.ts = header->ts; p.caplen = header->caplen; p.len = header->len;
    p.data.resize(header->caplen);
    std::memcpy(p.data.data(), bytes, header->caplen);
    q->push(std::move(p));
}

void worker(ThreadSafeQueue &q, int id) {
    while (g_running.load()) {
        Packet p;
        if (!q.pop(p)) break;
        std::ostringstream os;
        os << "[W" << id << "] ts=" << p.ts.tv_sec << "." << std::setw(6) << std::setfill('0') << p.ts.tv_usec
           << " caplen=" << p.caplen << " first=";
        size_t n = std::min<size_t>(p.data.size(), 12);
        for (size_t i=0;i<n;++i) {
            os << std::hex << std::setw(2) << std::setfill('0') << (int)p.data[i] << (i+1<n ? " " : "");
        }
        os << std::dec;
        std::cout << os.str() << std::endl;

		parse_and_print(p);
    }
}

void sigint_handler(int) {
    g_running.store(false);
    if (g_handle) pcap_breakloop(g_handle);
}

int main(int argc, char* argv[]){

	char errbuff[PCAP_ERRBUF_SIZE];
	const char* device = nullptr;

	if(argc > 1) device = argv[1];
	else device = pcap_lookupdev(errbuff);

	if(!device){
		std::cerr << "pcap_lookupdev failed :" << errbuff << std :: endl;
		return 1;
	}

	std::cout << "[+] Using Device : "<< device << std::endl;

	pcap_t* handle = pcap_open_live(device,65535,1,1000,errbuff);

	if(!handle){
		std::cerr << "pcap_open_live failed"<< errbuff << std::endl;
		return 1;
	}

	std::cout << "[+] Opened handle \n";

	// std::cout << "Capturing 5 packets\n";
	// pcap_loop(handle,5,packet_handler,nullptr);
	
	// pcap_close(handle);
	// std::cout<<"Done\n";

	g_handle = handle;
    signal(SIGINT, sigint_handler);

    ThreadSafeQueue q;
    // start workers
    int num_workers = std::max(1u, std::thread::hardware_concurrency()/2u);
    std::vector<std::thread> workers;
    for (int i=0;i<num_workers;++i) workers.emplace_back(worker, std::ref(q), i);

    std::cout << "Capturing... workers=" << num_workers << "\n";
    int ret = pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char*>(&q));
    if (ret == -1) std::cerr << "pcap_loop error: " << pcap_geterr(handle) << std::endl;
    else if (ret == -2) std::cout << "pcap_loop break\n";

    q.close();
    for (auto &t : workers) if (t.joinable()) t.join();
    pcap_close(handle);
	return 0;

}
