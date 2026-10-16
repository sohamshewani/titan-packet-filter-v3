#include <chrono>
#include <iostream>
#include <vector>
#include <numeric>
#include <algorithm>
#include <cstdint>
#include <iomanip>

// Mocking the 'titan-packet-filter' interface for self-contained compilation and benchmarking
namespace titan {
    struct Packet {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        uint8_t  protocol;
        const uint8_t* payload;
        size_t payload_len;
    };

    enum class FilterResult {
        ALLOW,
        DROP,
        REDIRECT
    };

    class PacketFilter {
    public:
        PacketFilter() = default;
        
        // Simulates filter rule compilation/setup
        bool initialize() {
            return true;
        }

        // The core operation we are benchmarking
        inline FilterResult evaluate(const Packet& pkt) {
            // Simulate realistic packet inspection workload (branching, bitwise checks)
            if (pkt.protocol == 6 && pkt.dst_port == 80) {
                return FilterResult::ALLOW;
            }
            if (pkt.src_ip == 0xC0A801015) { // 192.168.1.1 roughly
                return FilterResult::DROP;
            }
            if (pkt.payload_len > 1024) {
                return FilterResult::REDIRECT;
            }
            return FilterResult::ALLOW;
        }
    };
}

int main() {
    constexpr size_t WARMUP_ITERATIONS = 100000;
    constexpr size_t BENCHMARK_ITERATIONS = 5000000;

    titan::PacketFilter filter;
    if (!filter.initialize()) {
        std::cerr << "Failed to initialize titan-packet-filter\n";
        return 1;
    }

    uint8_t dummy_payload[512] = {0};
    titan::Packet sample_packet{
        0xC0A80102,
        0x0A000001,
        12345,
        80,
        6,
        dummy_payload,
        sizeof(dummy_payload)
    };

    // Warmup phase
    for (size_t i = 0; i < WARMUP_ITERATIONS; ++i) {
        volatile auto res = filter.evaluate(sample_packet);
        (void)res;
    }

    // Latency tracking container
    std::vector<uint64_t> latencies;
    latencies.reserve(BENCHMARK_ITERATIONS);

    // Benchmark execution
    auto start_time = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        auto pkt_start = std::chrono::high_resolution_clock::now();
        
        volatile auto res = filter.evaluate(sample_packet);
        (void)res;

        auto pkt_end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(pkt_end - pkt_start).count();
        
        latencies.push_back(static_cast<uint64_t>(duration));
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    auto total_duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();

    // Compute metrics
    double total_seconds = static_cast<double>(total_duration_ns) / 1e9;
    double ops_sec = static_cast<double>(BENCHMARK_ITERATIONS) / total_seconds;

    // Sort latencies for percentiles
    std::sort(latencies.begin(), latencies.end());

    uint64_t p50 = latencies[BENCHMARK_ITERATIONS * 50 / 100];
    uint64_t p90 = latencies[BENCHMARK_ITERATIONS * 90 / 100];
    uint64_t p99 = latencies[BENCHMARK_ITERATIONS * 99 / 100];
    uint64_t p999 = latencies[static_cast<size_t>(BENCHMARK_ITERATIONS * 99.9 / 100)];

    // Output formatted tabular metrics
    std::cout << "\n=========================================================\n";
    std::cout << "         TITAN-PACKET-FILTER MICROBENCHMARK RESULTS      \n";
    std::cout << "=========================================================\n";
    std::cout << "Metric                  | Value                          \n";
    std::cout << "---------------------------------------------------------\n";
    std::cout << "Total Iterations        | " << BENCHMARK_ITERATIONS << "\n";
    std::cout << "Total Duration (s)      | " << std::fixed << std::setprecision(4) << total_seconds << "\n";
    std::cout << "Throughput (ops/sec)    | " << std::setprecision(2) << ops_sec << "\n";
    std::cout << "---------------------------------------------------------\n";
    std::cout << "Latency p50 (ns)        | " << p50 << "\n";
    std::cout << "Latency p90 (ns)        | " << p90 << "\n";
    std::cout << "Latency p99 (ns)        | " << p99 << "\n";
    std::cout << "Latency p99.9 (ns)      | " << p999 << "\n";
    std::cout << "=========================================================\n";

    return 0;
}