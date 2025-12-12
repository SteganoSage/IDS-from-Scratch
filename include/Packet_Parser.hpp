#pragma once
#include "Packet.hpp"
#include "Headers.hpp"
#include <optional>
#include <string>

struct ParsedPacket {
    // ethernet
    uint16_t ethertype{0};

    // ip
    bool is_ipv4{false};
    std::string src_ip;
    std::string dst_ip;
    uint8_t ip_proto{0};
    size_t ip_header_len{0};

    // transport
    bool is_tcp{false};
    bool is_udp{false};
    uint16_t src_port{0};
    uint16_t dst_port{0};
    size_t l4_header_len{0};

    // payload
    const uint8_t* payload{nullptr};
    size_t payload_len{0};
};

std::optional<ParsedPacket> parse_packet(const Packet &pkt);
