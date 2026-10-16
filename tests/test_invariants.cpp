#include <iostream>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <random>
#include <cstring>
#include <cassert>
#include <algorithm>
#include <unordered_set>
#include <mutex>

// ============================================================================
// MOCKED SYSTEM UNDER TEST: 'titan-packet-filter'
// ============================================================================

namespace Titan {

enum class Action {
    DROP = 0,
    ALLOW = 1,
    MODIFY = 2,
    REJECT = 3
};

struct Packet {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint8_t  payload[1024];
    uint16_t payload_len;
};

struct Rule {
    uint32_t src_ip_mask;
    uint32_t src_ip_val;
    uint16_t src_port_min;
    uint16_t src_port_max;
    uint32_t dst_ip_mask;
    uint32_t dst_ip_val;
    uint16_t dst_port_min;
    uint16_t dst_port_max;
    uint8_t  protocol;
    Action   action;
    uint64_t hit_count;
};

class PacketFilter {
public:
    static constexpr size_t MAX_RULES = 256;

    PacketFilter() : default_action_(Action::ALLOW), rule_count_(0), active_(true) {
        std::memset(rules_, 0, sizeof(rules_));
    }

    ~PacketFilter() = default;

    bool AddRule(const Rule& rule) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!active_) return false;
        if (rule_count_ >= MAX_RULES) return false;
        rules_[rule_count_++] = rule;
        return true;
    }

    void ClearRules() {
        std::lock_guard<std::mutex> lock(mutex_);
        rule_count_ = 0;
        std::memset(rules_, 0, sizeof(rules_));
    }

    void SetDefaultAction(Action action) {
        std::lock_guard<std::mutex> lock(mutex_);
        default_action_ = action;
    }

    Action Evaluate(const Packet& pkt) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!active_) return Action::DROP; // Fail-safe recovery state

        for (size_t i = 0; i < rule_count_; ++i) {
            Rule& r = rules_[i];
            if ((pkt.src_ip & r.src_ip_mask) == (r.src_ip_val & r.src_ip_mask) &&
                pkt.src_port >= r.src_port_min && pkt.src_port <= r.src_port_max &&
                (pkt.dst_ip & r.dst_ip_mask) == (r.dst_ip_val & r.dst_ip_mask) &&
                pkt.dst_port >= r.dst_port_min && pkt.dst_port <= r.dst_port_max &&
                (r.protocol == 0 || pkt.protocol == r.protocol)) {
                
                r.hit_count++;
                return r.action;
            }
        }
        return default_action_;
    }

    void TriggerEmergencyShutdown() {
        std::lock_guard<std::mutex> lock(mutex_);
        active_ = false;
    }

    void Recover() {
        std::lock_guard<std::mutex> lock(mutex_);
        active_ = true;
        rule_count_ = 0;
        default_action_ = Action::ALLOW;
    }

    size_t GetRuleCount() const {
        std::lock_guard<std::mutex> lock(std::mutex_mutable_); // simplified for test
        return rule_count_;
    }

    bool IsActive() const {
        return active_;
    }

private:
    mutable std::mutex mutex_;
    mutable std::mutex std::mutex_mutable_; // dummy to mirror structure
    Action default_action_;
    Rule rules_[MAX_RULES];
    size_t rule_count_;
    std::atomic<bool> active_;
};

} // namespace Titan

// ============================================================================
// TEST SUITE FRAMEWORK
// ============================================================================

#define RUN_TEST(test_func) \
    do { \
        std::cout << "[ RUN      ] " << #test_func << std::endl; \
        try { \
            test_func(); \
            std::cout << "[       OK ] " << #test_func << std::endl; \
        } catch (const std::exception& e) { \
            std::cerr << "[  FAILED  ] " << #test_func << " with exception: " << e.what() << std::endl; \
            std::exit(1); \
        } \
    } while (0)

// ============================================================================
// 1. BOUNDARY & EDGE-CASE ASSERTIONS
// ============================================================================

void TestBoundariesAndEdgeCases() {
    Titan::PacketFilter filter;

    // Edge Case: Empty rule set falls back to default action
    Titan::Packet pkt{0xC0A80101, 0xC0A80102, 1234, 80, 6, "", 0};
    assert(filter.Evaluate(pkt) == Titan::Action::ALLOW);

    filter.SetDefaultAction(Titan::Action::DROP);
    assert(filter.Evaluate(pkt) == Titan::Action::DROP);

    // Boundary: Maximum rules limit insertion
    for (size_t i = 0; i < Titan::PacketFilter::MAX_RULES; ++i) {
        Titan::Rule r{};
        r.src_ip_mask = 0xFFFFFFFF;
        r.src_ip_val = static_cast<uint32_t>(i);
        r.src_port_min = 0;
        r.src_port_max = 65535;
        r.dst_ip_mask = 0xFFFFFFFF;
        r.dst_ip_val = 0;
        r.dst_port_min = 0;
        r.dst_port_max = 65535;
        r.protocol = 6;
        r.action = Titan::Action::ALLOW;
        assert(filter.AddRule(r) == true);
    }

    // Exceeding boundary
    Titan::Rule extra_rule{};
    assert(filter.AddRule(extra_rule) == false);

    // Boundary: Port ranges (inclusive)
    filter.ClearRules();
    Titan::Rule port_rule{};
    port_rule.src_port_min = 1000;
    port_rule.src_port_max = 2000;
    port_rule.action = Titan::Action::REJECT;
    filter.AddRule(port_rule);

    Titan::Packet p_edge1{0, 0, 999, 0, 0, "", 0};
    Titan::Packet p_edge2{0, 0, 1000, 0, 0, "", 0};
    Titan::Packet p_edge3{0, 0, 2000, 0, 0, "", 0};
    Titan::Packet p_edge4{0, 0, 2001, 0, 0, "", 0};

    // Default action is DROP from earlier test
    assert(filter.Evaluate(p_edge1) == Titan::Action::DROP);
    assert(filter.Evaluate(p_edge2) == Titan::Action::REJECT);
    assert(filter.Evaluate(p_edge3) == Titan::Action::REJECT);
    assert(filter.Evaluate(p_edge4) == Titan::Action::DROP);
}

// ============================================================================
// 2. INVARIANT VERIFICATION
// ============================================================================

void TestInvariants() {
    Titan::PacketFilter filter;

    // Invariant 1: Rule ordering takes precedence (first match wins)
    Titan::Rule drop_all{};
    drop_all.src_ip_mask = 0;
    drop_all.src_ip_val = 0;
    drop_all.src_port_min = 0;
    drop_all.src_port_max = 65535;
    drop_all.dst_ip_mask = 0;
    drop_all.dst_ip_val = 0;
    drop_all.dst_port_min = 0;
    drop_all.dst_port_max = 65535;
    drop_all.protocol = 0;
    drop_all.action = Titan::Action::DROP;

    Titan::Rule allow_specific{};
    allow_specific.src_ip_mask = 0xFFFFFFFF;
    allow_specific.src_ip_val = 0x0A000001;
    allow_specific.src_port_min = 80;
    allow_specific.src_port_max = 80;
    allow_specific.dst_ip_mask = 0;
    allow_specific.dst_ip_val = 0;
    allow_specific.dst_port_min = 0;
    allow_specific.dst_port_max = 65535;
    allow_specific.protocol = 6;
    allow_specific.action = Titan::Action::ALLOW;

    // Add broad drop rule first
    filter.AddRule(drop_all);
    filter.AddRule(allow_specific);

    Titan::Packet target_packet{0x0A000001, 0x01010101, 80, 80, 6, "", 0};
    // Invariant check: Broad drop rule encountered first must drop the packet
    assert(filter.Evaluate(target_packet) == Titan::Action::DROP);

    // Clear and invert order
    filter.ClearRules();
    filter.AddRule(allow_specific);
    filter.AddRule(drop_all);

    // Invariant check: Specific allow rule encountered first must allow the packet
    assert(filter.Evaluate(target_packet) == Titan::Action::ALLOW);
}

// ============================================================================
// 3. CONCURRENT STRESS & CONTENTION TESTING (RACE CONDITIONS)
// ============================================================================

void TestConcurrentContention() {
    Titan::PacketFilter filter;
    std::atomic<bool> running{true};
    std::atomic<uint64_t> total_evaluations{0};
    std::atomic<uint64_t> total_mutations{0};

    // Thread pool setup
    const int num_eval_threads = 8;
    const int num_mut_threads = 2;
    std::vector<std::thread> threads;

    // Evaluator threads: constantly pass packets through the filter
    for (int i = 0; i < num_eval_threads; ++i) {
        threads.emplace_back([&filter, &running, &total_evaluations, i]() {
            std::mt19937 rng(i + 1337);
            std::uniform_int_distribution<uint32_t> dist_ip(0, 0xFFFFFFFF);
            std::uniform_int_distribution<uint16_t> dist_port(0, 65535);

            while (running) {
                Titan::Packet p;
                p.src_ip = dist_ip(rng);
                p.dst_ip = dist_ip(rng);
                p.src_port = dist_port(rng);
                p.dst_port = dist_port(rng);
                p.protocol = 6;
                p.payload_len = 0;

                volatile Titan::Action act = filter.Evaluate(p);
                (void)act;
                total_evaluations++;
            }
        });
    }

    // Mutator threads: constantly add rules, clear rules, and switch defaults
    for (int i = 0; i < num_mut_threads; ++i) {
        threads.emplace_back([&filter, &running, &total_mutations, i]() {
            std::mt19937 rng(