#pragma once
#include "FeaturesDictBuilder.hpp"
#include "Flow.hpp"
#include <string>
#include <vector>
#include <sstream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>

// ---------------------------------------------------------------------------
// FeatureSender — sends a single expired flow's 68 features to the ML server
// via HTTP POST (JSON body) on localhost.
//
// Uses a raw POSIX socket — no libcurl dependency.
// Each call opens a new connection, sends the request, reads the response,
// and closes. Simple and stateless — good enough for flow-rate workloads.
//
// Usage:
//   FeatureSender sender("127.0.0.1", 5000);
//   sender.send(flow_key, features);  // called per expired flow
// ---------------------------------------------------------------------------
class FeatureSender {
public:
    FeatureSender(const std::string &host = "127.0.0.1", int port = 5000)
        : host_(host), port_(port) {}

    // Send one flow's features to POST /predict
    // Returns true on success, false on connection/send error.
    bool send(const FlowKey &key, const std::vector<float> &features)
    {
        if (features.size() != FeatureDictBuilder::FEATURE_COUNT) {
            std::cerr << "[FeatureSender] wrong feature count: "
                      << features.size() << "\n";
            return false;
        }

        const char* const* names = FeatureDictBuilder::feature_names();
        std::ostringstream body;
        body << "{\"features\":{";
        for (size_t i = 0; i < features.size(); ++i) {
            body << "\"" << names[i] << "\":" << features[i];
            if (i + 1 < features.size()) body << ",";
        }
        // Include basic flow metadata for logging on Python side
        body << "},\"meta\":{"
             << "\"src_ip\":"   << key.src_ip   << ","
             << "\"dst_ip\":"   << key.dst_ip   << ","
             << "\"src_port\":" << key.src_port << ","
             << "\"dst_port\":" << key.dst_port << ","
             << "\"protocol\":" << static_cast<int>(key.protocol)
             << "}}";

        const std::string body_str = body.str();

        // ── Build HTTP request ────────────────────────────────────────────
        std::ostringstream req;
        req << "POST /predict HTTP/1.1\r\n"
            << "Host: " << host_ << ":" << port_ << "\r\n"
            << "Content-Type: application/json\r\n"
            << "Content-Length: " << body_str.size() << "\r\n"
            << "Connection: close\r\n"
            << "\r\n"
            << body_str;

        const std::string req_str = req.str();

        // ── Connect ───────────────────────────────────────────────────────
        int sock = ::socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            std::cerr << "[FeatureSender] socket() failed\n";
            return false;
        }

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(static_cast<uint16_t>(port_));
        if (::inet_pton(AF_INET, host_.c_str(), &addr.sin_addr) <= 0) {
            std::cerr << "[FeatureSender] inet_pton failed for: " << host_ << "\n";
            ::close(sock);
            return false;
        }

        if (::connect(sock,
                      reinterpret_cast<struct sockaddr*>(&addr),
                      sizeof(addr)) < 0) {
            static bool warned = false;
            if (!warned) {
                std::cerr << "[FeatureSender] connect failed — is ml_server.py running on "
                          << host_ << ":" << port_ << "?\n";
                warned = true;
            }
            ::close(sock);
            return false;
        }

        // ── Send ──────────────────────────────────────────────────────────
        ssize_t sent = ::send(sock, req_str.c_str(), req_str.size(), 0);
        if (sent < 0) {
            std::cerr << "[FeatureSender] send() failed\n";
            ::close(sock);
            return false;
        }

        // ── Read response (just enough to confirm 200 OK) ─────────────────
        char buf[256];
        ::recv(sock, buf, sizeof(buf) - 1, 0);
        ::close(sock);
        return true;
    }

private:
    std::string host_;
    int         port_;
};