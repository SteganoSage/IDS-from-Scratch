#pragma once
#include <cstdint>
#include <cmath>
#include <limits>

// ---------------------------------------------------------------------------
// RunningStats — O(1) online statistics using Welford's algorithm.
//
// Tracks: count, mean, variance, stddev, min, max
// Used by: LengthStats, IATStats, ActivityStats
//
// All values stored as double for numerical stability.
// No heap allocation. No dynamic memory. Safe to copy/move.
// ---------------------------------------------------------------------------
struct RunningStats {
    uint64_t count{0};
    double   mean{0.0};
    double   M2{0.0};                              // Welford accumulator
    double   min{std::numeric_limits<double>::max()};
    double   max{std::numeric_limits<double>::lowest()};

    // Update with a new sample — O(1)
    inline void update(double x) noexcept {
        count++;
        double delta = x - mean;
        mean        += delta / static_cast<double>(count);
        M2          += delta * (x - mean);         // Welford's second pass
        if (x < min) min = x;
        if (x > max) max = x;
    }

    // Population variance (divide by N, matches CICFlowMeter behaviour)
    inline double variance() const noexcept {
        return (count < 1) ? 0.0 : M2 / static_cast<double>(count);
    }

    // Population standard deviation
    inline double stddev() const noexcept {
        return std::sqrt(variance());
    }

    // Safe accessors — return 0 when no samples seen
    inline double safe_min() const noexcept {
        return (count == 0) ? 0.0 : min;
    }
    inline double safe_max() const noexcept {
        return (count == 0) ? 0.0 : max;
    }
    inline double safe_mean() const noexcept {
        return mean;   // Welford mean is always valid (0.0 when count==0)
    }
};