#ifndef TITAN_FILTER_ENGINE_HPP
#define TITAN_FILTER_ENGINE_HPP

#include <cstdint>
#include <cstddef>
#include <atomic>
#include <array>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <functional>
#include <string_view>

#include "include/titan/arena.hpp"
#include "include/titan/types.hpp"
#include "include/titan/ring_buffer.hpp"
#include "include/titan/flow_control.hpp"
#include "include/titan/poll_loop.hpp"

namespace titan {

enum class FilterVerdict : uint8_t {
    Allow = 0,
    Drop,
    Redirect,
    RateLimited
};

enum class FilterEngineError : uint8_t {
    Success = 0,
    ArenaExhausted,
    RingBufferFull,
    FlowControlBlocked,
    InvalidPacketDescriptor,
    RuleExecutionFailure
};

class FilterEngineCategory : public std::error_category {
public:
    const char* name() const noexcept override {
        return "titan_filter_engine";
    }

    std::string message(int ev) const override {
        switch (static_cast<FilterEngineError>(ev)) {
            case FilterEngineError::Success:
                return "Success";
            case FilterEngineError::ArenaExhausted:
                return "Arena allocator exhausted, fail-safe backup engaged";
            case FilterEngineError::RingBufferFull:
                return "Ring buffer saturated, drop-tail policy applied";
            case FilterEngineError::FlowControlBlocked:
                return "Sliding-window flow control limit exceeded";
            case FilterEngineError::InvalidPacketDescriptor:
                return "Malformed or empty packet descriptor span";
            case FilterEngineError::RuleExecutionFailure:
                return "Internal failure executing filter rule chain";
            default:
                return "Unknown filter engine error";
        }
    }
};

inline const std::error_category& get_filter_engine_category() noexcept {
    static FilterEngineCategory instance;
    return instance;
}

inline std::error_code make_error_code(FilterEngineError e) noexcept {
    return {static_cast<int>(e), get_filter_engine_category()};
}

} // namespace titan

namespace std {
template <>
struct is_error_code_enum<titan::FilterEngineError> : true_type {};
} // namespace std

namespace titan {

struct alignas(64) FilterEngineMetrics {
    std::atomic<uint64_t> total_packets_processed{0};
    std::atomic<uint64_t> packets_allowed{0};
    std::atomic<uint64_t> packets_dropped{0};
    std::atomic<uint64_t> packets_rate_limited{0};
    std::atomic<uint64_t> arena_fallback_count{0};
    std::atomic<uint64_t> ring_saturation_count{0};
    std::atomic<uint64_t> processing_errors{0};
};

using FilterRuleCallback = std::function<FilterVerdict(const PacketDescriptor&, Arena&)>;

class alignas(64) FilterEngine {
public:
    struct Config {
        size_t max_rules_per_packet{64};
        bool enable_flow_control{true};
        bool strict_arena_bounds{true};
    };

    explicit FilterEngine(Arena& primary_arena, 
                          Arena& backup_arena,
                          FlowControl& flow_controller,
                          Config config = Config{})
        : primary_arena_(primary_arena),
          backup_arena_(backup_arena),
          flow_controller_(flow_controller),
          config_(config),
          running_(false) {}

    ~FilterEngine() {
        stop();
    }

    FilterEngine(const FilterEngine&) = delete;
    FilterEngine& operator=(const FilterEngine&) = delete;
    FilterEngine(FilterEngine&&) noexcept = delete;
    FilterEngine& operator=(FilterEngine&&) noexcept = delete;

    void start() noexcept {
        running_.store(true, std::memory_order_release);
    }

    void stop() noexcept {
        running_.store(false, std::memory_order_release);
    }

    [[nodiscard]] std::expected<FilterVerdict, std::error_code> process_packet(const PacketDescriptor& packet) noexcept {
        if (!running_.load(std::memory_order_acquire)) {
            return std::unexpected(make_error_code(FilterEngineError::RuleExecutionFailure));
        }

        if (packet.data.empty() || packet.data.data() == nullptr) {
            metrics_.processing_errors.fetch_add(1, std::memory_order_relaxed);
            return std::unexpected(make_error_code(FilterEngineError::InvalidPacketDescriptor));
        }

        metrics_.total_packets_processed.fetch_add(1, std::memory_order_relaxed);

        if (config_.enable_flow_control) {
            if (!flow_controller_.allow_request(packet.flow_id, packet.timestamp_ns)) {
                metrics_.packets_rate_limited.fetch_add(1, std::memory_order_relaxed);
                metrics_.packets_dropped.fetch_add(1, std::memory_order_relaxed);
                return FilterVerdict::RateLimited;
            }
        }

        Arena* active_arena = &primary_arena_;
        if (active_arena->is_exhausted(packet.data.size())) {
            metrics_.arena_fallback_count.fetch_add(1, std::memory_order_relaxed);
            active_arena = &backup_arena_;
            if (active_arena->is_exhausted(packet.data.size())) {
                metrics_.processing_errors.fetch_add(1, std::memory_order_relaxed);
                return std::unexpected(make_error_code(FilterEngineError::ArenaExhausted));
            }
        }

        void* scratch_mem = active_arena->allocate(packet.data.size(), 64);
        if (scratch_mem == nullptr) {
            metrics_.processing_errors.fetch_add(1, std::memory_order_relaxed);
            return std::unexpected(make_error_code(FilterEngineError::ArenaExhausted));
        }

        FilterVerdict current_verdict = FilterVerdict::Allow;

        for (const auto& rule : rule_chain_) {
            current_verdict = rule(packet, *active_arena);
            if (current_verdict != FilterVerdict::Allow) {
                break;
            }
        }

        if (current_verdict == FilterVerdict::Allow || current_verdict == FilterVerdict::Redirect) {
            metrics_.packets_allowed.fetch_add(1, std::memory_order_relaxed);
        } else {
            metrics_.packets_dropped.fetch_add(1, std::memory_order_relaxed);
        }

        return current_verdict;
    }

    void register_rule(FilterRuleCallback rule) {
        if (rule) {
            rule_chain_.push_back(std::move(rule));
        }
    }

    void clear_rules() noexcept {
        rule_chain_.clear();
    }

    [[nodiscard]] const FilterEngineMetrics& get_metrics() const noexcept {
        return metrics_;
    }

    void reset_metrics() noexcept {
        metrics_.total_packets_processed.store(0, std::memory_order_relaxed);
        metrics_.packets_allowed.store(0, std::memory_order_relaxed);
        metrics_.packets_dropped.store(0, std::memory_order_relaxed);
        metrics_.packets_rate_limited.store(0, std::memory_order_relaxed);
        metrics_.arena_fallback_count.store(0, std::memory_order_relaxed);
        metrics_.ring_saturation_count.store(0, std::memory_order_relaxed);
        metrics_.processing_errors.store(0, std::memory_order_relaxed);
    }

private:
    Arena& primary_arena_;
    Arena& backup_arena_;
    FlowControl& flow_controller_;
    Config config_;
    
    std::atomic<bool> running_;
    FilterEngineMetrics metrics_;
    std::vector<FilterRuleCallback> rule_chain_;
};

} // namespace titan

#endif // TITAN_FILTER_ENGINE_HPP