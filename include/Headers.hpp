#pragma once

#include <cstdint>
#include <arpa/inet.h>
#include <string>
#include <sstream>
#include <iomanip>

#pragma pack(push,1)

struct EthernetHeader{
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
    
    uint16_t ntoh_ethertype() const { return ntohs(ethertype);}
};

struct IPv4Header{
    uint8_t version_ihl;
    uint8_t dscp_ecn;
    uint16_t total_length;   
    uint16_t identification;
    uint16_t flags_fragment; 
    uint8_t  ttl;
    uint8_t  protocol;      
    uint16_t header_checksum;
    uint32_t src_addr;       
    uint32_t dst_addr;       

    uint8_t version() const { return version_ihl >> 4; }
    uint8_t ihl() const { return version_ihl & 0x0F; } // number of 32-bit words
    uint16_t ntoh_total_length() const { return ntohs(total_length); }
    uint32_t ntoh_src_addr() const { return ntohl(src_addr); }
    uint32_t ntoh_dst_addr() const { return ntohl(dst_addr); }

    std::size_t header_length_bytes() const { return static_cast<std::size_t>(ihl()) * 4; }
};

struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset_reserved; // data offset (upper 4 bits), reserved (lower 4 bits)
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
    // options may follow (data_offset indicates total TCP header length)

    uint16_t ntoh_src_port() const { return ntohs(src_port); }
    uint16_t ntoh_dst_port() const { return ntohs(dst_port); }
    uint8_t data_offset_words() const { return (data_offset_reserved >> 4) & 0x0F; } // in 32-bit words
    std::size_t header_length_bytes() const { return static_cast<std::size_t>(data_offset_words()) * 4; }

    // flag helpers
    bool fin() const { return flags & 0x01; }
    bool syn() const { return flags & 0x02; }
    bool rst() const { return flags & 0x04; }
    bool psh() const { return flags & 0x08; }
    bool ack() const { return flags & 0x10; }
    bool urg() const { return flags & 0x20; }
};

// --- UDP header (8 bytes) ---
struct UDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;

    uint16_t ntoh_src_port() const { return ntohs(src_port); }
    uint16_t ntoh_dst_port() const { return ntohs(dst_port); }
    uint16_t ntoh_length() const { return ntohs(length); }
};

#pragma pack(pop)

// --- small helpers (to format IP and MAC) ---
inline std::string format_ipv4(uint32_t ip_host_order) {
    uint8_t a = (ip_host_order >> 24) & 0xFF;
    uint8_t b = (ip_host_order >> 16) & 0xFF;
    uint8_t c = (ip_host_order >> 8) & 0xFF;
    uint8_t d = ip_host_order & 0xFF;
    std::ostringstream os;
    os << int(a) << "." << int(b) << "." << int(c) << "." << int(d);
    return os.str();
}

inline std::string format_mac(const uint8_t mac[6]) {
    std::ostringstream os;
    os << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        os << std::setw(2) << int(mac[i]);
        if (i + 1 < 6) os << ":";
    }
    os << std::dec;
    return os.str();
}



