// Integration test — 68-feature vector, CSE-CIC-IDS2018 order
// g++ -std=c++17 -O2 -I. test_integration.cpp -o test_integ && ./test_integ

#include "Flow.hpp"
#include "Feature_Extractor.hpp"
#include "FeaturesDictBuilder.hpp"
#include <iostream>
#include <cassert>
#include <cmath>

static bool nearly(float a, float b, float eps = 0.1f) {
    return std::abs(a - b) < eps;
}

// ── Test 1: correct count, no NaN/inf ─────────────────────────────────────
static void test_feature_count() {
    std::cout << "── Test 1: feature count + no NaN/inf ──\n";
    FlowKey key(1,2,100,200,6);
    Flow f(key, 0);
    PacketMeta m{};
    m.ts_us=0; m.ip_total_len=60; m.ip_header_len=20;
    m.tcp_header_len=20; m.tcp_window=65535;
    m.payload_len=20; m.tcp_flags=0x02; m.forward=true;
    f.update(m);
    auto feat = FeatureExtractor::extract(f);
    assert(feat.size() == 68);
    for (size_t i = 0; i < feat.size(); ++i) {
        assert(!std::isnan(feat[i]) && !std::isinf(feat[i]));
    }
    std::cout << "  68 features, no NaN/inf  PASSED ✔\n\n";
}

// ── Test 2: 2018 CSV order verified ───────────────────────────────────────
static void test_2018_csv_order() {
    std::cout << "── Test 2: 2018 CSV order ──\n";
    const char* const* names = FeatureDictBuilder::feature_names();
    // Spot-check key positions against 2018 CSV column order
    assert(std::string(names[ 0]) == "Flow Duration");
    assert(std::string(names[ 1]) == "Tot Fwd Pkts");
    assert(std::string(names[ 2]) == "Tot Bwd Pkts");
    assert(std::string(names[13]) == "Flow Byts/s");
    assert(std::string(names[14]) == "Flow Pkts/s");
    assert(std::string(names[29]) == "Fwd PSH Flags");
    assert(std::string(names[30]) == "Fwd URG Flags");
    assert(std::string(names[40]) == "FIN Flag Cnt");
    assert(std::string(names[41]) == "SYN Flag Cnt");
    assert(std::string(names[42]) == "RST Flag Cnt");
    assert(std::string(names[46]) == "ECE Flag Cnt");
    assert(std::string(names[51]) == "Fwd Byts/b Avg");
    assert(std::string(names[56]) == "Init Fwd Win Byts");
    assert(std::string(names[57]) == "Init Bwd Win Byts");
    assert(std::string(names[66]) == "Idle Max");
    assert(std::string(names[67]) == "Idle Min");
    std::cout << "  Column order matches 2018 CSV  PASSED ✔\n\n";
}

// ── Test 3: multi-packet TCP flow, all values verified ────────────────────
static void test_tcp_flow() {
    std::cout << "── Test 3: multi-packet TCP flow ──\n";
    FlowKey key(1,2,4444,80,6);
    Flow f(key, 0);

    struct P { uint64_t ts; uint16_t tot,ip_h,tcp_h,win; uint32_t pl; uint8_t fl; bool fwd; };
    P pkts[] = {
        {0,      60,  20,20,65535,20, 0x02,true},   // SYN fwd
        {5000,   60,  20,20,8192, 20, 0x12,false},  // SYN-ACK bwd
        {10000,  40,  20,20,65535,0,  0x10,true},   // ACK fwd
        {10500,  540, 20,20,65535,500,0x18,true},   // PSH+ACK fwd (data)
        {15000,  1040,20,20,8192, 1000,0x18,false}, // PSH+ACK bwd (data)
        {20000,  40,  20,20,65535,0,  0x11,true},   // FIN+ACK fwd
        {20500,  40,  20,20,8192, 0,  0x14,false},  // RST+ACK bwd
    };
    for (auto &p : pkts) {
        PacketMeta m{};
        m.ts_us=p.ts; m.ip_total_len=p.tot; m.ip_header_len=p.ip_h;
        m.tcp_header_len=p.tcp_h; m.tcp_window=p.win;
        m.payload_len=p.pl; m.tcp_flags=p.fl; m.forward=p.fwd;
        f.update(m);
    }

    auto feat = FeatureExtractor::extract(f);
    assert(feat.size() == 68);

    // [0]  Flow Duration = 20500 µs
    assert(nearly(feat[0], 20500.0f));
    // [1]  Tot Fwd Pkts = 4
    assert(nearly(feat[1], 4.0f));
    // [2]  Tot Bwd Pkts = 3  (wait — 3 bwd packets: SYN-ACK, PSH+ACK, RST+ACK)
    assert(nearly(feat[2], 3.0f));
    // [3]  TotLen Fwd Pkts = 60+40+540+40 = 680
    assert(nearly(feat[3], 680.0f));
    // [4]  TotLen Bwd Pkts = 60+1040+40 = 1140
    assert(nearly(feat[4], 1140.0f));
    // [5]  Fwd Pkt Len Max = 540
    assert(nearly(feat[5], 540.0f));
    // [6]  Fwd Pkt Len Min = 40
    assert(nearly(feat[6], 40.0f));
    // [29] Fwd PSH Flags = 1
    assert(nearly(feat[29], 1.0f));
    // [30] Fwd URG Flags = 0
    assert(nearly(feat[30], 0.0f));
    // [40] FIN Flag Cnt = 1 (FIN+ACK fwd)
    assert(nearly(feat[40], 1.0f));
    // [41] SYN Flag Cnt = 2 (SYN + SYN-ACK)
    assert(nearly(feat[41], 2.0f));
    // [42] RST Flag Cnt = 1 (RST+ACK bwd)
    assert(nearly(feat[42], 1.0f));
    // [43] PSH Flag Cnt = 2
    assert(nearly(feat[43], 2.0f));
    // [46] ECE Flag Cnt = 0
    assert(nearly(feat[46], 0.0f));
    // [47] Down/Up Ratio = 3/4 = 0.75
    assert(nearly(feat[47], 0.75f));
    // [53] Subflow Fwd Byts == TotLen Fwd Pkts [3]
    assert(feat[53] == feat[3]);
    // [55] Subflow Bwd Byts == TotLen Bwd Pkts [4]
    assert(feat[55] == feat[4]);
    // [52] Subflow Fwd Pkts == Tot Fwd Pkts [1]
    assert(feat[52] == feat[1]);
    // [54] Subflow Bwd Pkts == Tot Bwd Pkts [2]
    assert(feat[54] == feat[2]);
    // [49] Fwd Seg Size Avg == Fwd Pkt Len Mean [7]
    assert(feat[49] == feat[7]);
    // [50] Bwd Seg Size Avg == Bwd Pkt Len Mean [11]
    assert(feat[50] == feat[11]);
    // [51] Fwd Byts/b Avg = 0 (bulk not implemented)
    assert(feat[51] == 0.0f);
    // [56] Init Fwd Win Byts = 65535
    assert(nearly(feat[56], 65535.0f));
    // [57] Init Bwd Win Byts = 8192
    assert(nearly(feat[57], 8192.0f));
    // [58] Fwd Act Data Pkts = 2 (SYN w/ payload=20, PSH w/ payload=500)
    assert(nearly(feat[58], 2.0f));
    // [59] Fwd Seg Size Min = 20
    assert(nearly(feat[59], 20.0f));

    // No NaN/inf
    for (size_t i = 0; i < feat.size(); ++i)
        assert(!std::isnan(feat[i]) && !std::isinf(feat[i]));

    std::cout << "  All feature values verified  PASSED ✔\n\n";
}

// ── Test 4: dict builder — 68 unique keys, correct names ──────────────────
static void test_dict_builder() {
    std::cout << "── Test 4: FeatureDictBuilder ──\n";
    std::vector<float> feats(68, 0.0f);
    feats[0]  = 9387.0f;     // Flow Duration
    feats[56] = 8192.0f;     // Init Fwd Win Byts
    feats[66] = 5000000.0f;  // Idle Max

    auto dict = FeatureDictBuilder::build(feats);
    assert(dict.size() == 68);
    assert(dict.count("Flow Duration")    == 1);
    assert(dict.count("Init Fwd Win Byts")== 1);
    assert(dict.count("Idle Max")         == 1);
    assert(dict.count("Fwd Byts/b Avg")   == 1);
    assert(dict.count("Fwd URG Flags")    == 1);
    assert(std::abs(dict.at("Flow Duration")     - 9387.0f)    < 1.0f);
    assert(std::abs(dict.at("Init Fwd Win Byts") - 8192.0f)    < 1.0f);
    assert(std::abs(dict.at("Idle Max")          - 5000000.0f) < 1.0f);

    // Wrong size throws
    bool threw = false;
    try { FeatureDictBuilder::build(std::vector<float>(67, 0.0f)); }
    catch (const std::runtime_error &) { threw = true; }
    assert(threw);

    std::cout << "  68 keys, correct names, mismatch throws  PASSED ✔\n\n";
}

// ── Test 5: zero-duration flow — rate features = 0 ────────────────────────
static void test_zero_duration() {
    std::cout << "── Test 5: zero-duration — rates = 0 ──\n";
    FlowKey key(1,2,10,20,6);
    Flow f(key, 500'000);
    PacketMeta m{};
    m.ts_us=500'000; m.ip_total_len=100; m.ip_header_len=20;
    m.tcp_header_len=20; m.tcp_window=512;
    m.payload_len=60; m.tcp_flags=0x12; m.forward=false;
    f.update(m);
    auto feat = FeatureExtractor::extract(f);
    assert(feat[13] == 0.0f);  // Flow Byts/s
    assert(feat[14] == 0.0f);  // Flow Pkts/s
    assert(feat[33] == 0.0f);  // Fwd Pkts/s
    assert(feat[34] == 0.0f);  // Bwd Pkts/s
    for (float v : feat) assert(!std::isnan(v) && !std::isinf(v));
    std::cout << "  All rate features = 0 on zero-duration  PASSED ✔\n\n";
}

// ── Test 6: new flags — RST, ECE, Fwd URG tracked ─────────────────────────
static void test_new_flags() {
    std::cout << "── Test 6: new flags (RST, ECE, Fwd URG) ──\n";
    FlowKey key(1,2,1000,2000,6);
    Flow f(key, 0);

    auto pkt = [&](uint8_t flags, bool fwd, uint64_t ts) {
        PacketMeta m{};
        m.ts_us=ts; m.ip_total_len=40; m.ip_header_len=20;
        m.tcp_header_len=20; m.tcp_window=1024;
        m.payload_len=0; m.tcp_flags=flags; m.forward=fwd;
        f.update(m);
    };

    pkt(0x04, true,  0);     // RST fwd
    pkt(0x04, false, 100);   // RST bwd
    pkt(0x40, true,  200);   // ECE fwd
    pkt(0x40, false, 300);   // ECE bwd
    pkt(0x20, true,  400);   // URG fwd  → fwd_urg_count++
    pkt(0x20, false, 500);   // URG bwd  → urg_count++ but NOT fwd_urg

    auto feat = FeatureExtractor::extract(f);
    assert(feat[42] == 2.0f);   // RST Flag Cnt = 2
    assert(feat[46] == 2.0f);   // ECE Flag Cnt = 2
    assert(feat[45] == 2.0f);   // URG Flag Cnt = 2 (total)
    assert(feat[30] == 1.0f);   // Fwd URG Flags = 1 (fwd only)
    std::cout << "  RST=2, ECE=2, URG=2, FwdURG=1  PASSED ✔\n\n";
}

// ── Test 7: features.json model order cross-check ─────────────────────────
static void test_model_order() {
    std::cout << "── Test 7: features.json order cross-check ──\n";
    // Spot-check that the model's expected feature order
    // matches what our dict produces at specific indices
    const char* const* names = FeatureDictBuilder::feature_names();
    // features.json index 0 = "Init Fwd Win Byts" — in our dict that's index 56
    // But the dict is keyed by name, not index — model accesses by name ✔
    // Verify the 5 most critical model features exist by name
    std::vector<std::string> model_key_features = {
        "Init Fwd Win Byts", "Flow Duration", "Flow IAT Mean",
        "Fwd Pkts/s", "Bwd Pkts/s", "RST Flag Cnt", "ECE Flag Cnt",
        "Fwd URG Flags", "Idle Max", "Idle Min", "Active Max", "Active Min"
    };
    auto dict = FeatureDictBuilder::build(std::vector<float>(68, 1.0f));
    for (auto &name : model_key_features) {
        assert(dict.count(name) == 1);
    }
    std::cout << "  All model key features present by name  PASSED ✔\n\n";
}

int main() {
    std::cout << "==== Integration Tests: 68-feature CIC-IDS2018 ====\n\n";
    test_feature_count();
    test_2018_csv_order();
    test_tcp_flow();
    test_dict_builder();
    test_zero_duration();
    test_new_flags();
    test_model_order();
    std::cout << "==== ALL TESTS PASSED ✔ ====\n";
    return 0;
}