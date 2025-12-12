#include <iostream>
#include <vector>
#include <thread>
#include <csignal>
#include <atomic>

#include "Capture.hpp"
#include "Queue.hpp"
#include "Worker.hpp"
#include "Rules.hpp"
#include "Rule_Parser.hpp"

static CaptureEngine *g_cap = nullptr;
static std::atomic<bool> g_running{true};

void handle_sigint(int) {
    g_running.store(false);
    if (g_cap) g_cap->break_loop();
}

int main(int argc, char* argv[]) {
    std::string dev;
    if (argc > 1) dev = argv[1];
    else {
        std::cerr << "Usage: sudo ./ids <interface>\n";
        return 1;
    }

    RuleParser parser;
    auto rules = parser.parse_file("config/local.txt");
    std::cout << "[+] Loaded " << rules.size() << " rules\n";

    // create queue
    ThreadSafeQueue queue;

    // install signal handler
    std::signal(SIGINT, handle_sigint);

    // start workers
    unsigned int num_workers = std::max(1u, std::thread::hardware_concurrency() / 2);
    std::vector<std::thread> workers;
    for (unsigned int i = 0; i < num_workers; ++i) {
        Worker w(queue, static_cast<int>(i), g_running, rules);
        workers.emplace_back(std::thread(std::move(w)));
    }

    // open capture
    CaptureEngine cap;
    g_cap = &cap;
    std::string err;
    if (!cap.open_live(dev, 65535, true, 1000, &err)) {
        std::cerr << "pcap_open_live failed: " << err << "\n";
        // signal workers to stop and join
        queue.close();
        for (auto &t : workers) if (t.joinable()) t.join();
        return 1;
    }

    std::cout << "[+] capture started on " << dev << " workers=" << num_workers << "\n";
    int ret = cap.loop(0, &queue); // block until break
    if (ret == -1) {
        std::cerr << "pcap_loop error: " << pcap_geterr(nullptr) << "\n";
    } else if (ret == -2) {
        std::cout << "[*] pcap_loop terminated via break\n";
    } else {
        std::cout << "[*] pcap_loop exited: " << ret << "\n";
    }

    // cleanup
    queue.close();
    for (auto &t : workers) if (t.joinable()) t.join();
    cap.close();
    g_cap = nullptr;
    std::cout << "[+] shutdown complete\n";
    return 0;
}
