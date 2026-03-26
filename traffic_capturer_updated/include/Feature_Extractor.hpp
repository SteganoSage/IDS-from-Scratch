#pragma once
#include "Flow.hpp"
#include <vector>
#include <cmath>

// ---------------------------------------------------------------------------
// FeatureExtractor — produces the 68-feature vector required by the model,
// in exact CSE-CIC-IDS2018 CSV column order (dropping the 8 unused columns).
//
// ┌─────┬──────────────────────┬───────────────────────────────────────────┐
// │ Idx │ 2018 Feature Name    │ Source                                    │
// ├─────┼──────────────────────┼───────────────────────────────────────────┤
// │  0  │ Flow Duration        │ flow.duration_us()           (µs)         │
// │  1  │ Tot Fwd Pkts         │ flow.volume.total_fwd_packets()           │
// │  2  │ Tot Bwd Pkts         │ flow.volume.total_bwd_packets()           │
// │  3  │ TotLen Fwd Pkts      │ flow.length.total_len_fwd()               │
// │  4  │ TotLen Bwd Pkts      │ flow.length.total_len_bwd()               │
// │  5  │ Fwd Pkt Len Max      │ flow.length.fwd_pkt_len_max()             │
// │  6  │ Fwd Pkt Len Min      │ flow.length.fwd_pkt_len_min()             │
// │  7  │ Fwd Pkt Len Mean     │ flow.length.fwd_pkt_len_mean()            │
// │  8  │ Fwd Pkt Len Std      │ flow.length.fwd_pkt_len_std()             │
// │  9  │ Bwd Pkt Len Max      │ flow.length.bwd_pkt_len_max()             │
// │ 10  │ Bwd Pkt Len Min      │ flow.length.bwd_pkt_len_min()             │
// │ 11  │ Bwd Pkt Len Mean     │ flow.length.bwd_pkt_len_mean()            │
// │ 12  │ Bwd Pkt Len Std      │ flow.length.bwd_pkt_len_std()             │
// │ 13  │ Flow Byts/s          │ total_bytes / duration_s                  │
// │ 14  │ Flow Pkts/s          │ total_packets / duration_s                │
// │ 15  │ Flow IAT Mean        │ flow.iat.flow_iat_mean()                  │
// │ 16  │ Flow IAT Std         │ flow.iat.flow_iat_std()                   │
// │ 17  │ Flow IAT Max         │ flow.iat.flow_iat_max()                   │
// │ 18  │ Flow IAT Min         │ flow.iat.flow_iat_min()                   │
// │ 19  │ Fwd IAT Tot          │ flow.iat.fwd_iat_total_val()              │
// │ 20  │ Fwd IAT Mean         │ flow.iat.fwd_iat_mean()                   │
// │ 21  │ Fwd IAT Std          │ flow.iat.fwd_iat_std()                    │
// │ 22  │ Fwd IAT Max          │ flow.iat.fwd_iat_max()                    │
// │ 23  │ Fwd IAT Min          │ flow.iat.fwd_iat_min()                    │
// │ 24  │ Bwd IAT Tot          │ flow.iat.bwd_iat_total_val()              │
// │ 25  │ Bwd IAT Mean         │ flow.iat.bwd_iat_mean()                   │
// │ 26  │ Bwd IAT Std          │ flow.iat.bwd_iat_std()                    │
// │ 27  │ Bwd IAT Max          │ flow.iat.bwd_iat_max()                    │
// │ 28  │ Bwd IAT Min          │ flow.iat.bwd_iat_min()                    │
// │ 29  │ Fwd PSH Flags        │ flow.tcp.fwd_psh_flags()                  │
// │ 30  │ Fwd URG Flags        │ flow.tcp.fwd_urg_flags()                  │
// │ 31  │ Fwd Header Len       │ flow.headers.fwd_header_length()          │
// │ 32  │ Bwd Header Len       │ flow.headers.bwd_header_length()          │
// │ 33  │ Fwd Pkts/s           │ total_fwd_pkts / duration_s               │
// │ 34  │ Bwd Pkts/s           │ total_bwd_pkts / duration_s               │
// │ 35  │ Pkt Len Min          │ flow.length.min_pkt_len()                 │
// │ 36  │ Pkt Len Max          │ flow.length.max_pkt_len()                 │
// │ 37  │ Pkt Len Mean         │ flow.length.pkt_len_mean()                │
// │ 38  │ Pkt Len Std          │ flow.length.pkt_len_std()                 │
// │ 39  │ Pkt Len Var          │ flow.length.pkt_len_variance()            │
// │ 40  │ FIN Flag Cnt         │ flow.tcp.fin_flag_count()                 │
// │ 41  │ SYN Flag Cnt         │ flow.tcp.syn_flag_count()                 │
// │ 42  │ RST Flag Cnt         │ flow.tcp.rst_flag_count()                 │
// │ 43  │ PSH Flag Cnt         │ flow.tcp.psh_flag_count()                 │
// │ 44  │ ACK Flag Cnt         │ flow.tcp.ack_flag_count()                 │
// │ 45  │ URG Flag Cnt         │ flow.tcp.urg_flag_count()                 │
// │ 46  │ ECE Flag Cnt         │ flow.tcp.ece_flag_count()                 │
// │ 47  │ Down/Up Ratio        │ bwd_pkts / fwd_pkts (0 if fwd==0)        │
// │ 48  │ Pkt Size Avg         │ total_bytes / total_packets               │
// │ 49  │ Fwd Seg Size Avg     │ flow.length.fwd_pkt_len_mean()  [alias]   │
// │ 50  │ Bwd Seg Size Avg     │ flow.length.bwd_pkt_len_mean()  [alias]   │
// │ 51  │ Fwd Byts/b Avg       │ 0.0  (bulk detection not implemented)     │
// │ 52  │ Subflow Fwd Pkts     │ flow.volume.total_fwd_packets() [alias]   │
// │ 53  │ Subflow Fwd Byts     │ flow.length.total_len_fwd()     [alias]   │
// │ 54  │ Subflow Bwd Pkts     │ flow.volume.total_bwd_packets() [alias]   │
// │ 55  │ Subflow Bwd Byts     │ flow.length.total_len_bwd()     [alias]   │
// │ 56  │ Init Fwd Win Byts    │ flow.tcp.init_win_bytes_forward()         │
// │ 57  │ Init Bwd Win Byts    │ flow.tcp.init_win_bytes_backward()        │
// │ 58  │ Fwd Act Data Pkts    │ flow.tcp.act_data_pkts_fwd()              │
// │ 59  │ Fwd Seg Size Min     │ flow.tcp.min_seg_size_forward()           │
// │ 60  │ Active Mean          │ flow.activity.active_mean()               │
// │ 61  │ Active Std           │ flow.activity.active_std()                │
// │ 62  │ Active Max           │ flow.activity.active_max()                │
// │ 63  │ Active Min           │ flow.activity.active_min()                │
// │ 64  │ Idle Mean            │ flow.activity.idle_mean()                 │
// │ 65  │ Idle Std             │ flow.activity.idle_std()                  │
// │ 66  │ Idle Max             │ flow.activity.idle_max()                  │
// │ 67  │ Idle Min             │ flow.activity.idle_min()                  │
// └─────┴──────────────────────┴───────────────────────────────────────────┘
//
// Note on Fwd Byts/b Avg [51]:
//   CICFlowMeter's bulk-transfer stats require detecting "bulk state"
//   (>=4 consecutive packets in same direction within 1s). Always 0 in
//   practice for most flows. The model was trained on the 2018 dataset
//   where this column is 0 for the vast majority of flows. We output 0.0f.
// ---------------------------------------------------------------------------

class FeatureExtractor {
public:

    static constexpr size_t FEATURE_COUNT = 68;

    // extract() — call once per expired flow.
    // Calls activity.finish() internally; do not call before this.
    static std::vector<float> extract(Flow &flow)
    {
        flow.activity.finish();

        std::vector<float> f;
        f.reserve(FEATURE_COUNT);

        // Pre-compute shared values
        const double dur_us  = static_cast<double>(flow.duration_us());
        const double dur_s   = dur_us / 1'000'000.0;
        const double tot_pkt = static_cast<double>(flow.volume.total_pkt_count());
        const double tot_byt = static_cast<double>(flow.total_bytes());
        const double fwd_pkt = static_cast<double>(flow.volume.total_fwd_packets());
        const double bwd_pkt = static_cast<double>(flow.volume.total_bwd_packets());

        // [0]  Flow Duration (µs)
        f.push_back(static_cast<float>(dur_us));

        // [1]  Tot Fwd Pkts
        f.push_back(static_cast<float>(fwd_pkt));

        // [2]  Tot Bwd Pkts
        f.push_back(static_cast<float>(bwd_pkt));

        // [3]  TotLen Fwd Pkts
        f.push_back(static_cast<float>(flow.length.total_len_fwd()));

        // [4]  TotLen Bwd Pkts
        f.push_back(static_cast<float>(flow.length.total_len_bwd()));

        // [5]  Fwd Pkt Len Max
        f.push_back(static_cast<float>(flow.length.fwd_pkt_len_max()));

        // [6]  Fwd Pkt Len Min
        f.push_back(static_cast<float>(flow.length.fwd_pkt_len_min()));

        // [7]  Fwd Pkt Len Mean
        f.push_back(static_cast<float>(flow.length.fwd_pkt_len_mean()));

        // [8]  Fwd Pkt Len Std
        f.push_back(static_cast<float>(flow.length.fwd_pkt_len_std()));

        // [9]  Bwd Pkt Len Max
        f.push_back(static_cast<float>(flow.length.bwd_pkt_len_max()));

        // [10] Bwd Pkt Len Min
        f.push_back(static_cast<float>(flow.length.bwd_pkt_len_min()));

        // [11] Bwd Pkt Len Mean
        f.push_back(static_cast<float>(flow.length.bwd_pkt_len_mean()));

        // [12] Bwd Pkt Len Std
        f.push_back(static_cast<float>(flow.length.bwd_pkt_len_std()));

        // [13] Flow Byts/s
        f.push_back(safe_div(static_cast<float>(tot_byt),
                             static_cast<float>(dur_s)));

        // [14] Flow Pkts/s
        f.push_back(safe_div(static_cast<float>(tot_pkt),
                             static_cast<float>(dur_s)));

        // [15] Flow IAT Mean
        f.push_back(static_cast<float>(flow.iat.flow_iat_mean()));

        // [16] Flow IAT Std
        f.push_back(static_cast<float>(flow.iat.flow_iat_std()));

        // [17] Flow IAT Max
        f.push_back(static_cast<float>(flow.iat.flow_iat_max()));

        // [18] Flow IAT Min
        f.push_back(static_cast<float>(flow.iat.flow_iat_min()));

        // [19] Fwd IAT Tot
        f.push_back(static_cast<float>(flow.iat.fwd_iat_total_val()));

        // [20] Fwd IAT Mean
        f.push_back(static_cast<float>(flow.iat.fwd_iat_mean()));

        // [21] Fwd IAT Std
        f.push_back(static_cast<float>(flow.iat.fwd_iat_std()));

        // [22] Fwd IAT Max
        f.push_back(static_cast<float>(flow.iat.fwd_iat_max()));

        // [23] Fwd IAT Min
        f.push_back(static_cast<float>(flow.iat.fwd_iat_min()));

        // [24] Bwd IAT Tot
        f.push_back(static_cast<float>(flow.iat.bwd_iat_total_val()));

        // [25] Bwd IAT Mean
        f.push_back(static_cast<float>(flow.iat.bwd_iat_mean()));

        // [26] Bwd IAT Std
        f.push_back(static_cast<float>(flow.iat.bwd_iat_std()));

        // [27] Bwd IAT Max
        f.push_back(static_cast<float>(flow.iat.bwd_iat_max()));

        // [28] Bwd IAT Min
        f.push_back(static_cast<float>(flow.iat.bwd_iat_min()));

        // [29] Fwd PSH Flags
        f.push_back(static_cast<float>(flow.tcp.fwd_psh_flags()));

        // [30] Fwd URG Flags
        f.push_back(static_cast<float>(flow.tcp.fwd_urg_flags()));

        // [31] Fwd Header Len
        f.push_back(static_cast<float>(flow.headers.fwd_header_length()));

        // [32] Bwd Header Len
        f.push_back(static_cast<float>(flow.headers.bwd_header_length()));

        // [33] Fwd Pkts/s
        f.push_back(safe_div(static_cast<float>(fwd_pkt),
                             static_cast<float>(dur_s)));

        // [34] Bwd Pkts/s
        f.push_back(safe_div(static_cast<float>(bwd_pkt),
                             static_cast<float>(dur_s)));

        // [35] Pkt Len Min
        f.push_back(static_cast<float>(flow.length.min_pkt_len()));

        // [36] Pkt Len Max
        f.push_back(static_cast<float>(flow.length.max_pkt_len()));

        // [37] Pkt Len Mean
        f.push_back(static_cast<float>(flow.length.pkt_len_mean()));

        // [38] Pkt Len Std
        f.push_back(static_cast<float>(flow.length.pkt_len_std()));

        // [39] Pkt Len Var
        f.push_back(static_cast<float>(flow.length.pkt_len_variance()));

        // [40] FIN Flag Cnt
        f.push_back(static_cast<float>(flow.tcp.fin_flag_count()));

        // [41] SYN Flag Cnt
        f.push_back(static_cast<float>(flow.tcp.syn_flag_count()));

        // [42] RST Flag Cnt
        f.push_back(static_cast<float>(flow.tcp.rst_flag_count()));

        // [43] PSH Flag Cnt
        f.push_back(static_cast<float>(flow.tcp.psh_flag_count()));

        // [44] ACK Flag Cnt
        f.push_back(static_cast<float>(flow.tcp.ack_flag_count()));

        // [45] URG Flag Cnt
        f.push_back(static_cast<float>(flow.tcp.urg_flag_count()));

        // [46] ECE Flag Cnt
        f.push_back(static_cast<float>(flow.tcp.ece_flag_count()));

        // [47] Down/Up Ratio = bwd_pkts / fwd_pkts
        f.push_back(safe_div(static_cast<float>(bwd_pkt),
                             static_cast<float>(fwd_pkt)));

        // [48] Pkt Size Avg = total_bytes / total_packets
        f.push_back(safe_div(static_cast<float>(tot_byt),
                             static_cast<float>(tot_pkt)));

        // [49] Fwd Seg Size Avg  (alias: Fwd Pkt Len Mean)
        f.push_back(static_cast<float>(flow.length.fwd_pkt_len_mean()));

        // [50] Bwd Seg Size Avg  (alias: Bwd Pkt Len Mean)
        f.push_back(static_cast<float>(flow.length.bwd_pkt_len_mean()));

        // [51] Fwd Byts/b Avg — bulk detection not implemented; always 0
        f.push_back(0.0f);

        // [52] Subflow Fwd Pkts  (alias: Tot Fwd Pkts)
        f.push_back(static_cast<float>(flow.volume.total_fwd_packets()));

        // [53] Subflow Fwd Byts  (alias: TotLen Fwd Pkts)
        f.push_back(static_cast<float>(flow.length.total_len_fwd()));

        // [54] Subflow Bwd Pkts  (alias: Tot Bwd Pkts)
        f.push_back(static_cast<float>(flow.volume.total_bwd_packets()));

        // [55] Subflow Bwd Byts  (alias: TotLen Bwd Pkts)
        f.push_back(static_cast<float>(flow.length.total_len_bwd()));

        // [56] Init Fwd Win Byts
        f.push_back(static_cast<float>(flow.tcp.init_win_bytes_forward()));

        // [57] Init Bwd Win Byts
        f.push_back(static_cast<float>(flow.tcp.init_win_bytes_backward()));

        // [58] Fwd Act Data Pkts
        f.push_back(static_cast<float>(flow.tcp.act_data_pkts_fwd()));

        // [59] Fwd Seg Size Min
        f.push_back(static_cast<float>(flow.tcp.min_seg_size_forward()));

        // [60] Active Mean
        f.push_back(static_cast<float>(flow.activity.active_mean()));

        // [61] Active Std
        f.push_back(static_cast<float>(flow.activity.active_std()));

        // [62] Active Max
        f.push_back(static_cast<float>(flow.activity.active_max()));

        // [63] Active Min
        f.push_back(static_cast<float>(flow.activity.active_min()));

        // [64] Idle Mean
        f.push_back(static_cast<float>(flow.activity.idle_mean()));

        // [65] Idle Std
        f.push_back(static_cast<float>(flow.activity.idle_std()));

        // [66] Idle Max
        f.push_back(static_cast<float>(flow.activity.idle_max()));

        // [67] Idle Min
        f.push_back(static_cast<float>(flow.activity.idle_min()));

        return f;  // exactly FEATURE_COUNT elements
    }

private:
    static inline float safe_div(float num, float denom) noexcept {
        return (std::abs(denom) < 1e-9f) ? 0.0f : num / denom;
    }
};