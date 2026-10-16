#ifndef TITAN_FLOW_CONTROL_HPP
#define TITAN_FLOW_CONTROL_HPP

#include <cstdint>
#include <atomic>
#include <chrono>
#include <new>

namespace titan {

struct FlowMetrics {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> allowed_packets{0};
    std::atomic<uint64_t> dropped_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> allowed_bytes{0};
    std::atomic<uint64_t> dropped_bytes{0};
};

enum class Disposition : uint8_t {
    Allow = 0,
    Drop = 1,
    Backpressure = 2
};

class alignas(64) SlidingWindowLimiter {
private:
    struct alignas(64) WindowBucket {
        std::atomic<uint64_t> timestamp_ns{0};
        std::atomic<uint64_t> packet_count{0};
        std::atomic<uint64_t> byte_count{0};
    };

    uint64_t max_packets_per_window_;
    uint64_t max_bytes_per_window_;
    uint64_t window_duration_ns_;
    uint32_t num_buckets_;
    
    WindowBucket* buckets_;
    FlowMetrics metrics_;

    uint64_t get_current_time_ns() const noexcept {
        auto now = std::chrono::steady_clock::now();
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            now.time_since_epoch()).count());
    }

public:
    SlidingWindowLimiter(uint64_t max_packets, uint64_t max_bytes, 
                         uint64_t window_duration_ms, uint32_t num_buckets = 10)
        : max_packets_per_window_(max_packets),
          max_bytes_per_window_(max_bytes),
          window_duration_ns_(window_duration_ms * 1'000'000ULL),
          num_buckets_(num_buckets == 0 ? 1 : num_buckets),
          buckets_(nullptr),
          metrics_() {
          
        size_t alloc_size = sizeof(WindowBucket) * num_buckets_;
        void* mem = ::operator new(alloc_size, std::align_val_align_t{64});
        buckets_ = static_cast<WindowBucket*>(mem);
        
        uint64_t init_time = get_current_time_ns();
        for (uint32_t i = 0; i < num_buckets_; ++i) {
            new (&buckets_[i]) WindowBucket();
            buckets_[i].timestamp_ns.store(init_time, std::memory_order_relaxed);
            buckets_[i].packet_count.store(0, std::memory_order_relaxed);
            buckets_[i].byte_count.store(0, std::memory_order_relaxed);
        }
    }

    ~SlidingWindowLimiter() noexcept {
        if (buckets_) {
            for (uint32_t i = 0; i < num_buckets_; ++i) {
                buckets_[i].~WindowBucket();
            }
            ::operator delete(buckets_, std::align_val_align_t{64});
            buckets_ = nullptr;
        }
    }

    SlidingWindowLimiter(const SlidingWindowLimiter&) = delete;
    SlidingWindowLimiter& operator=(const SlidingWindowLimiter&) = delete;
    SlidingWindowLimiter(SlidingWindowLimiter&&) = delete;
    SlidingWindowLimiter& operator=(SlidingWindowLimiter&&) = delete;

    Disposition evaluate(uint64_t packet_size) noexcept {
        metrics_.total_packets.fetch_add(1, std::memory_order_relaxed);
        metrics_.total_bytes.fetch_add(packet_size, std::memory_order_relaxed);

        uint64_t now = get_current_time_ns();
        uint64_t bucket_duration = window_duration_ns_ / num_buckets_;
        uint32_t current_bucket_idx = static_cast<uint32_t>((now / bucket_duration) % num_buckets_);

        WindowBucket& current_bucket = buckets_[current_bucket_idx];
        uint64_t bucket_ts = current_bucket.timestamp_ns.load(std::memory_order_acquire);

        if (now - bucket_ts >= bucket_duration) {
            uint64_t expected_ts = bucket_ts;
            if (current_bucket.timestamp_ns.compare_exchange_strong(
                    expected_ts, now, std::memory_order_acq_rel, std::memory_order_relaxed)) {
                current_bucket.packet_count.store(0, std::memory_order_release);
                current_bucket.byte_count.store(0, std::memory_order_release);
            }
        }

        uint64_t sliding_packets = 0;
        uint64_t sliding_bytes = 0;
        uint64_t window_start_threshold = (now > window_duration_ns_) ? (now - window_duration_ns_) : 0;

        for (uint32_t i = 0; i < num_buckets_; ++i) {
            WindowBucket& b = buckets_[i];
            uint64_t b_ts = b.timestamp_ns.load(std::memory_order_acquire);
            if (b_ts >= window_start_threshold) {
                sliding_packets += b.packet_count.load(std::memory_order_relaxed);
                sliding_bytes += b.byte_count.load(std::memory_order_relaxed);
            }
        }

        if (sliding_packets >= max_packets_per_window_ || 
            (sliding_bytes + packet_size) > max_bytes_per_window_) {
            metrics_.dropped_packets.fetch_add(1, std::memory_order_relaxed);
            metrics_.dropped_bytes.fetch_add(packet_size, std::memory_order_relaxed);
            
            if (sliding_packets >= (max_packets_per_window_ * 3) / 2) {
                return Disposition::Drop;
            }
            return Disposition::Backpressure;
        }

        current_bucket.packet_count.fetch_add(1, std::memory_order_relaxed);
        current_bucket.byte_count.fetch_add(packet_size, std::memory_order_relaxed);

        metrics_.allowed_packets.fetch_add(1, std::memory_order_relaxed);
        metrics_.allowed_bytes.fetch_add(packet_size, std::memory_order_relaxed);

        return Disposition::Allow;
    }

    const FlowMetrics& get_metrics() const noexcept {
        return metrics_;
    }

    void reset() noexcept {
        uint64_t init_time = get_current_time_ns();
        for (uint32_t i = 0; i < num_buckets_; ++i) {
            buckets_[i].timestamp_ns.store(init_time, std::memory_order_release);
            buckets_[i].packet_count.store(0, std::memory_order_release);
            buckets_[i].byte_count.store(0, std::memory_order_release);
        }
    }
};

} // namespace titan

#endif // TITAN_FLOW_CONTROL_HPP