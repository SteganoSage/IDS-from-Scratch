#include "Packet.hpp"
#include <cstring>

Packet::Packet(const timeval& t, uint32_t cap, uint32_t len_, const uint8_t* src) {
    ts = t;
    caplen = cap;
    len = len_;
    data.resize(caplen);
    if (src && caplen > 0) {
        std::memcpy(data.data(), src, caplen);
    }
}
