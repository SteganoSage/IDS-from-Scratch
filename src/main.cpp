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
