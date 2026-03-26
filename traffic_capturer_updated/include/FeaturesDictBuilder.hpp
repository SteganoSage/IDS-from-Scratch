#pragma once
#include <unordered_map>
#include <vector>
#include <string>
#include <stdexcept>

// ---------------------------------------------------------------------------
// FeatureDictBuilder — maps the 68-element feature vector to exact
// CSE-CIC-IDS2018 column names, in 2018 CSV column order.
// The returned map is passed directly to the ML model.
// ---------------------------------------------------------------------------
class FeatureDictBuilder {
public:

    static constexpr size_t FEATURE_COUNT = 68;

    // Ordered names — must match Feature_Extractor.hpp index-for-index
    static const char* const* feature_names() {
        static const char* const NAMES[FEATURE_COUNT] = {
            /*  0 */ "Flow Duration",
            /*  1 */ "Tot Fwd Pkts",
            /*  2 */ "Tot Bwd Pkts",
            /*  3 */ "TotLen Fwd Pkts",
            /*  4 */ "TotLen Bwd Pkts",
            /*  5 */ "Fwd Pkt Len Max",
            /*  6 */ "Fwd Pkt Len Min",
            /*  7 */ "Fwd Pkt Len Mean",
            /*  8 */ "Fwd Pkt Len Std",
            /*  9 */ "Bwd Pkt Len Max",
            /* 10 */ "Bwd Pkt Len Min",
            /* 11 */ "Bwd Pkt Len Mean",
            /* 12 */ "Bwd Pkt Len Std",
            /* 13 */ "Flow Byts/s",
            /* 14 */ "Flow Pkts/s",
            /* 15 */ "Flow IAT Mean",
            /* 16 */ "Flow IAT Std",
            /* 17 */ "Flow IAT Max",
            /* 18 */ "Flow IAT Min",
            /* 19 */ "Fwd IAT Tot",
            /* 20 */ "Fwd IAT Mean",
            /* 21 */ "Fwd IAT Std",
            /* 22 */ "Fwd IAT Max",
            /* 23 */ "Fwd IAT Min",
            /* 24 */ "Bwd IAT Tot",
            /* 25 */ "Bwd IAT Mean",
            /* 26 */ "Bwd IAT Std",
            /* 27 */ "Bwd IAT Max",
            /* 28 */ "Bwd IAT Min",
            /* 29 */ "Fwd PSH Flags",
            /* 30 */ "Fwd URG Flags",
            /* 31 */ "Fwd Header Len",
            /* 32 */ "Bwd Header Len",
            /* 33 */ "Fwd Pkts/s",
            /* 34 */ "Bwd Pkts/s",
            /* 35 */ "Pkt Len Min",
            /* 36 */ "Pkt Len Max",
            /* 37 */ "Pkt Len Mean",
            /* 38 */ "Pkt Len Std",
            /* 39 */ "Pkt Len Var",
            /* 40 */ "FIN Flag Cnt",
            /* 41 */ "SYN Flag Cnt",
            /* 42 */ "RST Flag Cnt",
            /* 43 */ "PSH Flag Cnt",
            /* 44 */ "ACK Flag Cnt",
            /* 45 */ "URG Flag Cnt",
            /* 46 */ "ECE Flag Cnt",
            /* 47 */ "Down/Up Ratio",
            /* 48 */ "Pkt Size Avg",
            /* 49 */ "Fwd Seg Size Avg",
            /* 50 */ "Bwd Seg Size Avg",
            /* 51 */ "Fwd Byts/b Avg",
            /* 52 */ "Subflow Fwd Pkts",
            /* 53 */ "Subflow Fwd Byts",
            /* 54 */ "Subflow Bwd Pkts",
            /* 55 */ "Subflow Bwd Byts",
            /* 56 */ "Init Fwd Win Byts",
            /* 57 */ "Init Bwd Win Byts",
            /* 58 */ "Fwd Act Data Pkts",
            /* 59 */ "Fwd Seg Size Min",
            /* 60 */ "Active Mean",
            /* 61 */ "Active Std",
            /* 62 */ "Active Max",
            /* 63 */ "Active Min",
            /* 64 */ "Idle Mean",
            /* 65 */ "Idle Std",
            /* 66 */ "Idle Max",
            /* 67 */ "Idle Min",
        };
        return NAMES;
    }

    static std::unordered_map<std::string, float>
    build(const std::vector<float> &features)
    {
        if (features.size() != FEATURE_COUNT) {
            throw std::runtime_error(
                "FeatureDictBuilder::build — expected " +
                std::to_string(FEATURE_COUNT) +
                " features, got " +
                std::to_string(features.size()));
        }

        const char* const* names = feature_names();
        std::unordered_map<std::string, float> dict;
        dict.reserve(FEATURE_COUNT);
        for (size_t i = 0; i < FEATURE_COUNT; ++i)
            dict.emplace(names[i], features[i]);
        return dict;
    }
};