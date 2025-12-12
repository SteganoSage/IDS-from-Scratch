#include "Packet_Parser.hpp"
#include <cstring>
#include <iostream>

std::optional<ParsedPacket> parse_packet(const Packet &pkt) {
    ParsedPacket out;
    const uint8_t* raw = pkt.data.data();
    size_t caplen = pkt.caplen;

    if (caplen < sizeof(EthernetHeader)) return std::nullopt;
    const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(raw);
    out.ethertype = eth->ntoh_ethertype();

    if (out.ethertype != 0x0800) {
        // not IPv4; we only handle IPv4 for now
        return std::nullopt;
    }

    size_t ip_off = sizeof(EthernetHeader);
    if (caplen < ip_off + sizeof(IPv4Header)) return std::nullopt;
    const IPv4Header* ip = reinterpret_cast<const IPv4Header*>(raw + ip_off);

    size_t ip_hdr_len = ip->header_length_bytes();
    if (ip_hdr_len < 20) return std::nullopt;
    if (caplen < ip_off + ip_hdr_len) return std::nullopt;

    out.is_ipv4 = true;
    out.ip_proto = ip->protocol;
    out.ip_header_len = ip_hdr_len;
    out.src_ip = format_ipv4(ip->ntoh_src_addr());
    out.dst_ip = format_ipv4(ip->ntoh_dst_addr());

    size_t l4_off = ip_off + ip_hdr_len;
    if (out.ip_proto == 6) { // TCP
        if (caplen < l4_off + sizeof(TCPHeader)) return std::nullopt;
        const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(raw + l4_off);
        size_t tcp_len = tcp->header_length_bytes();
        if (tcp_len < 20) return std::nullopt;
        if (caplen < l4_off + tcp_len) return std::nullopt;
        out.is_tcp = true;
        out.src_port = tcp->ntoh_src_port();
        out.dst_port = tcp->ntoh_dst_port();
        out.l4_header_len = tcp_len;
        out.payload = raw + l4_off + tcp_len;
        out.payload_len = 0;
        if ((l4_off + tcp_len) < caplen) out.payload_len = caplen - (l4_off + tcp_len);
    } else if (out.ip_proto == 17) { // UDP
        if (caplen < l4_off + sizeof(UDPHeader)) return std::nullopt;
        const UDPHeader* udp = reinterpret_cast<const UDPHeader*>(raw + l4_off);
        out.is_udp = true;
        out.src_port = udp->ntoh_src_port();
        out.dst_port = udp->ntoh_dst_port();
        out.l4_header_len = sizeof(UDPHeader);
        out.payload = raw + l4_off + out.l4_header_len;
        out.payload_len = 0;
        if ((l4_off + out.l4_header_len) < caplen) out.payload_len = caplen - (l4_off + out.l4_header_len);
    } else {
        // other protocols: we won't parse payload in day3
        return out;
    }

    return out;
}
