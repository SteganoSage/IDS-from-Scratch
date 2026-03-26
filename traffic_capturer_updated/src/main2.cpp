#include <iostream>
#include <vector>
#include <thread>
#include <csignal>
#include <atomic>
#include <string>
#include <cstring>
#include <iomanip>

#include "Capture.hpp"
#include "Queue.hpp"
#include "Worker.hpp"
#include "FlowTable.hpp"
#include "Feature_Extractor.hpp"
#include "FeaturesDictBuilder.hpp"

// Defined in worker.cpp — set here after pcap open so workers know datalink type
extern int g_datalink;

static CaptureEngine    *g_cap     = nullptr;
static ThreadSafeQueue  *g_queue   = nullptr;
static std::atomic<bool> g_running{true};

void handle_sigint(int) {
    g_running.store(false);
    if (g_cap)   g_cap->break_loop();
    if (g_queue) g_queue->close();
}

// Drain all remaining flows at shutdown and print them.
// Calls worker.print_expired() so names come from FeatureDictBuilder — no
// hardcoded array here.
static void drain_and_print(FlowTable &table, Worker &worker)
{
    auto remaining = table.expire_idle_flows(UINT64_MAX);
    if (remaining.empty()) return;
    std::cout << "\n[+] Draining " << remaining.size()
              << " remaining flow(s) at shutdown...\n";
    worker.print_expired(remaining);
}

static void print_usage(const char *prog) {
    std::cerr
        << "Usage:\n"
        << "  sudo " << prog << " <interface> [options]\n"
        << "\nOptions:\n"
        << "  --timeout <s>     Idle flow timeout in seconds  (default: 30)\n"
        << "  --workers <n>     Number of worker threads      (default: hw_concurrency/2)\n"
        << "  --expiry  <ms>    ExpiryThread interval in ms   (default: 5000)\n"
        << "  --filter  <bpf>   BPF capture filter            (default: \"ip and (tcp or udp)\")\n";
}

int main(int argc, char *argv[])
{
    if (argc < 2) { print_usage(argv[0]); return 1; }

    // ── Parse arguments ───────────────────────────────────────────────────
    std::string  iface;
    uint64_t     timeout_s   = 30;
    unsigned int num_workers = std::max(1u, std::thread::hardware_concurrency() / 2);
    uint64_t     expiry_ms   = 5'000;
    std::string  bpf_filter  = "ip and (tcp or udp)";

    for (int i = 1; i < argc; ++i) {
        if      (std::strcmp(argv[i], "--timeout") == 0 && i + 1 < argc)
            timeout_s = static_cast<uint64_t>(std::stoul(argv[++i]));
        else if (std::strcmp(argv[i], "--workers") == 0 && i + 1 < argc)
            num_workers = std::max(1u, static_cast<unsigned int>(std::stoul(argv[++i])));
        else if (std::strcmp(argv[i], "--expiry")  == 0 && i + 1 < argc)
            expiry_ms = static_cast<uint64_t>(std::stoul(argv[++i]));
        else if (std::strcmp(argv[i], "--filter")  == 0 && i + 1 < argc)
            bpf_filter = argv[++i];
        else if (argv[i][0] != '-')
            iface = argv[i];
        else {
            std::cerr << "Unknown option: " << argv[i] << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    if (iface.empty()) {
        std::cerr << "Error: specify a network interface\n";
        print_usage(argv[0]);
        return 1;
    }

    // ── Setup ─────────────────────────────────────────────────────────────
    FlowTable       flow_table(timeout_s * 1'000'000ULL);
    ThreadSafeQueue queue;
    g_queue = &queue;

    std::signal(SIGINT, handle_sigint);

    // ── Workers ───────────────────────────────────────────────────────────
    std::vector<Worker> worker_objs;
    worker_objs.reserve(num_workers);
    for (unsigned int i = 0; i < num_workers; ++i)
        worker_objs.emplace_back(queue, static_cast<int>(i), g_running, flow_table);

    std::vector<std::thread> worker_threads;
    worker_threads.reserve(num_workers);
    for (auto &w : worker_objs)
        worker_threads.emplace_back(std::ref(w));

    // ── ExpiryThread ──────────────────────────────────────────────────────
    // Runs on wall clock every expiry_ms. Expires idle flows regardless of
    // packet rate — handles port-scan case where traffic drops to zero after
    // a burst and packet-count triggers would never fire.
    ExpiryThread expiry(flow_table, g_running, worker_objs[0], expiry_ms);
    std::thread  expiry_thread(std::ref(expiry));

    // ── Capture ───────────────────────────────────────────────────────────
    CaptureEngine cap;
    g_cap = &cap;
    std::string err;

    if (!cap.open_live(iface, 65535, true, 1000, &err)) {
        std::cerr << "pcap_open_live failed: " << err << "\n";
        g_running.store(false);
        queue.close();
        for (auto &t : worker_threads) if (t.joinable()) t.join();
        expiry_thread.join();
        return 1;
    }

    if (!cap.set_filter(bpf_filter))
        std::cerr << "[!] BPF filter failed: " << cap.get_error()
                  << " — continuing without filter\n";

    // Detect datalink type — critical for Docker (LINUX_SLL) vs bare metal (Ethernet)
    g_datalink = cap.datalink();
    const char* dl_name = (g_datalink == 1)   ? "Ethernet (DLT_EN10MB)" :
                          (g_datalink == 113)  ? "Linux cooked (DLT_LINUX_SLL)" :
                                                 "Unknown";
    std::cout << "[+] Datalink type: " << g_datalink << " — " << dl_name << "\n";

    std::cout << "[+] Capture started on " << iface
              << " | workers="  << num_workers
              << " | timeout="  << timeout_s << "s"
              << " | expiry="   << expiry_ms  << "ms\n"
              << "[+] Press Ctrl+C to stop.\n";

    int ret = cap.loop(0, &queue);

    if      (ret == -1) std::cerr << "pcap_loop error: " << cap.get_error() << "\n";
    else if (ret == -2) std::cout << "[*] Stopped by signal\n";
    else                std::cout << "[*] pcap_loop exited: " << ret << "\n";

    // ── Graceful shutdown ─────────────────────────────────────────────────
    g_running.store(false);
    queue.close();
    for (auto &t : worker_threads) if (t.joinable()) t.join();
    expiry_thread.join();
    cap.close();
    g_cap   = nullptr;
    g_queue = nullptr;

    // Final drain — catches any flows not yet expired by ExpiryThread
    drain_and_print(flow_table, worker_objs[0]);

    std::cout << "\n[+] Shutdown complete."
              << " Dropped packets: " << queue.dropped_count() << "\n";
    return 0;
}