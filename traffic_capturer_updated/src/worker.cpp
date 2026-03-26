#include "Worker.hpp"
#include "Packet_Parser.hpp"
#include "Feature_Extractor.hpp"
#include "FeaturesDictBuilder.hpp"
#include "FeatureSender.hpp"
#include "Headers.hpp"
#include <iostream>
#include <iomanip>

// One sender instance — connects to ml_server.py on localhost:5000
static FeatureSender g_sender("127.0.0.1", 5000);

// Datalink type detected at startup — set by main() after open_live()
// DLT_EN10MB=1 (Ethernet), DLT_LINUX_SLL=113 (Docker/cooked)
int g_datalink = 1;

Worker::Worker(ThreadSafeQueue &q, int id,
               std::atomic<bool> &running_flag,
               FlowTable &flow_table)
    : queue_(q), id_(id), running_(running_flag), flow_table_(flow_table)
{}

void Worker::operator()()
{
    ParsedPacket parsed;

    while (running_.load()) {
        Packet pkt;
        if (!queue_.pop(pkt)) break;

        if (!parse_packet(pkt, parsed, g_datalink)) continue;

        // ── Timestamps ────────────────────────────────────────────────────
        // pcap_ts_us: actual packet capture time from pcap header.
        //   Used for ALL flow features (IAT, duration, active/idle).
        //   This is what CICFlowMeter uses — real wire timestamps.
        //
        // wall_ts_us: steady_clock wall time.
        //   Used ONLY for ExpiryThread idle detection.
        //   Stored separately in last_seen_ts_us so expiry logic works
        //   even when pcap replays old timestamps.
        const uint64_t pcap_ts_us =
            static_cast<uint64_t>(pkt.ts.tv_sec)  * 1'000'000ULL +
            static_cast<uint64_t>(pkt.ts.tv_usec);
        const uint64_t wall_ts_us = Worker::wall_clock_us();

        // Skip ICMP and other non-port-based protocols — no meaningful flow key
        if (!parsed.has_ports) continue;

        // ── Canonical flow key + direction ────────────────────────────────
        // Key: always (lower_ip, higher_ip, lower_ip_port, higher_ip_port, proto)
        // forward=true means this packet goes from lower_ip → higher_ip
        //
        // Fix: direction is determined by whether src_ip matches the key's
        // src_ip (lower IP), NOT by which IP is lower. This correctly marks
        // the FIRST packet of a TCP connection as forward regardless of IP.
        bool forward;
        FlowKey key;
        if (parsed.src_ip < parsed.dst_ip ||
           (parsed.src_ip == parsed.dst_ip && parsed.src_port < parsed.dst_port)) {
            key     = FlowKey(parsed.src_ip, parsed.dst_ip,
                              parsed.src_port, parsed.dst_port,
                              parsed.ip_proto);
            forward = true;
        } else if (parsed.src_ip > parsed.dst_ip ||
                   (parsed.src_ip == parsed.dst_ip && parsed.src_port > parsed.dst_port)) {
            key     = FlowKey(parsed.dst_ip, parsed.src_ip,
                              parsed.dst_port, parsed.src_port,
                              parsed.ip_proto);
            forward = false;
        } else {
            // src == dst, same port — loopback edge case, skip
            continue;
        }

        const PacketMeta meta = parsed.to_meta(pcap_ts_us, wall_ts_us, forward);
        flow_table_.update_flow(key, meta);
        ++packet_count_;

        // No expiry trigger here — ExpiryThread handles all flow expiration
        // on a fixed wall-clock interval, independent of packet rate.
    }

    std::cout << "[W" << id_ << "] exiting\n";
}

void Worker::print_expired(std::vector<Flow> &expired)
{
    const char* const* NAMES = FeatureDictBuilder::feature_names();

    for (Flow &f : expired) {
        const auto features = FeatureExtractor::extract(f);

        // Send to ML server — non-blocking best-effort
        g_sender.send(f.key, features);

        // Print to terminal
        std::cout << "\n[W" << id_ << "] ══════════════ FLOW EXPIRED ══════════════\n"
                  << "  proto     = " << static_cast<int>(f.key.protocol) << "\n"
                  << "  fwd_pkts  = " << f.volume.total_fwd_packets() << "\n"
                  << "  bwd_pkts  = " << f.volume.total_bwd_packets() << "\n"
                  << "  bytes     = " << f.total_bytes() << "\n"
                  << "  dur_us    = " << f.duration_us() << "\n"
                  << "  ┌─────┬──────────────────────┬─────────────────┐\n"
                  << "  │ Idx │ Feature Name         │ Value           │\n"
                  << "  ├─────┼──────────────────────┼─────────────────┤\n";

        for (size_t i = 0; i < features.size(); ++i) {
            std::cout << "  │ "
                      << std::setw(3) << std::right << i         << " │ "
                      << std::setw(20) << std::left  << NAMES[i] << " │ "
                      << std::setw(15) << std::right
                      << std::fixed << std::setprecision(4) << features[i]
                      << " │\n";
        }

        std::cout << "  └─────┴──────────────────────┴─────────────────┘\n";
    }
}