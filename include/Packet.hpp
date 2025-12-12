#pragma once
#include <vector>
#include <cstdint>
#include <sys/time.h>

struct Packet {
    timeval ts;
    uint32_t caplen;
    uint32_t len;
    std::vector<uint8_t> data;

    Packet() = default;
    Packet(const timeval& t, uint32_t cap, uint32_t len_, const uint8_t* src);
};
