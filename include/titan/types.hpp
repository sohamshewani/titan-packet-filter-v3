#ifndef TITAN_TYPES_HPP
#define TITAN_TYPES_HPP

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <array>
#include <utility>
#include <span>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcps.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

namespace titan {

enum class PacketDirection : uint8_t {
    Inbound  = 0x01,
    Outbound = 0x02,
    Forward  = 0x03
};

enum class L4Protocol : uint8_t {
    Unknown = 0x00,
    TCP     = 0x06,
    UDP     = 0x11,
    ICMP    = 0x01,
    ICMPv6  = 0x3A
};

enum class FilterVerdict : uint8_t {
    Allow       = 0x00,
    Drop        = 0x01,
    Redirect    = 0x02,
    RateLimit   = 0x03,
    Inspect     = 0x04
};

struct alignas(64) PacketMetadata {
    uint64_t timestamp_ns;
    uint32_t flow_hash;
    uint32_t ingress_ifindex;
    uint16_t vlan_id;
    L4Protocol l4_proto;
    PacketDirection direction;
    FilterVerdict verdict;
    uint8_t flags;
    std::array<uint8_t, 32> reserved;

    constexpr PacketMetadata() noexcept
        : timestamp_ns(0),
          flow_hash(0),
          ingress_ifindex(0),
          vlan_id(0),
          l4_proto(L4Protocol::Unknown),
          direction(PacketDirection::Inbound),
          verdict(FilterVerdict::Allow),
          flags(0),
          reserved{} {}
};

static_assert(sizeof(PacketMetadata) == 64, "PacketMetadata must be exactly 64 bytes (1 cache line)");
static_assert(alignof(PacketMetadata) == 64, "PacketMetadata must be 64-byte aligned");

class PacketDescriptor {
private:
    std::span<const uint8_t> raw_data_;
    PacketMetadata metadata_;
    const uint8_t* l3_header_;
    const uint8_t* l4_header_;
    const uint8_t* payload_;
    size_t l3_len_;
    size_t l4_len_;
    size_t payload_len_;

public:
    constexpr PacketDescriptor() noexcept
        : raw_data_(),
          metadata_(),
          l3_header_(nullptr),
          l4_header_(nullptr),
          payload_(nullptr),
          l3_len_(0),
          l4_len_(0),
          payload_len_(0) {}

    explicit PacketDescriptor(std::span<const uint8_t> dma_span, uint64_t ts_ns = 0, uint32_t ifindex = 0) noexcept
        : raw_data_(dma_span),
          metadata_(),
          l3_header_(nullptr),
          l4_header_(nullptr),
          payload_(nullptr),
          l3_len_(0),
          l4_len_(0),
          payload_len_(0) {
        metadata_.timestamp_ns = ts_ns;
        metadata_.ingress_ifindex = ifindex;
        parse_headers();
    }

    PacketDescriptor(const PacketDescriptor&) noexcept = default;
    PacketDescriptor& operator=(const PacketDescriptor&) noexcept = default;
    PacketDescriptor(PacketDescriptor&&) noexcept = default;
    PacketDescriptor& operator=(PacketDescriptor&&) noexcept = default;

    ~PacketDescriptor() noexcept = default;

    [[nodiscard]] constexpr std::span<const uint8_t> data() const noexcept {
        return raw_data_;
    }

    [[nodiscard]] constexpr const uint8_t* data_ptr() const noexcept {
        return raw_data_.data();
    }

    [[nodiscard]] constexpr size_t size() const noexcept {
        return raw_data_.size();
    }

    [[nodiscard]] constexpr bool empty() const noexcept {
        return raw_data_.empty();
    }

    [[nodiscard]] constexpr const PacketMetadata& metadata() const noexcept {
        return metadata_;
    }

    [[nodiscard]] constexpr PacketMetadata& metadata() noexcept {
        return metadata_;
    }

    [[nodiscard]] constexpr std::span<const uint8_t> l3_span() const noexcept {
        return {l3_header_, l3_len_};
    }

    [[nodiscard]] constexpr std::span<const uint8_t> l4_span() const noexcept {
        return {l4_header_, l4_len_};
    }

    [[nodiscard]] constexpr std::span<const uint8_t> payload_span() const noexcept {
        return {payload_, payload_len_};
    }

    [[nodiscard]] const struct ether_header* eth_header() const noexcept {
        if (raw_data_.size() < sizeof(struct ether_header)) {
            return nullptr;
        }
        return reinterpret_cast<const struct ether_header*>(raw_data_.data());
    }

    [[nodiscard]] const struct iphdr* ipv4_header() const noexcept {
        if (metadata_.l4_proto == L4Protocol::TCP || metadata_.l4_proto == L4Protocol::UDP || metadata_.l4_proto == L4Protocol::ICMP) {
            if (l3_len_ >= sizeof(struct iphdr)) {
                return reinterpret_cast<const struct iphdr*>(l3_header_);
            }
        }
        return nullptr;
    }

    [[nodiscard]] const struct ip6_hdr* ipv6_header() const noexcept {
        if (metadata_.l4_proto == L4Protocol::TCP || metadata_.l4_proto == L4Protocol::UDP || metadata_.l4_proto == L4Protocol::ICMPv6) {
            if (l3_len_ >= sizeof(struct ip6_hdr)) {
                return reinterpret_cast<const struct ip6_hdr*>(l3_header_);
            }
        }
        return nullptr;
    }

    [[nodiscard]] const struct tcphdr* tcp_header() const noexcept {
        if (metadata_.l4_proto == L4Protocol::TCP && l4_len_ >= sizeof(struct tcphdr)) {
            return reinterpret_cast<const struct tcphdr*>(l4_header_);
        }
        return nullptr;
    }

    [[nodiscard]] const struct udphdr* udp_header() const noexcept {
        if (metadata_.l4_proto == L4Protocol::UDP && l4_len_ >= sizeof(struct udphdr)) {
            return reinterpret_cast<const struct udphdr*>(l4_header_);
        }
        return nullptr;
    }

    void set_verdict(FilterVerdict v) noexcept {
        metadata_.verdict = v;
    }

    void set_flow_hash(uint32_t hash) noexcept {
        metadata_.flow_hash = hash;
    }

private:
    void parse_headers() noexcept {
        if (raw_data_.size() < sizeof(struct ether_header)) {
            return;
        }

        const uint8_t* ptr = raw_data_.data();
        size_t rem = raw_data_.size();

        const auto* eth = reinterpret_cast<const struct ether_header*>(ptr);
        ptr += sizeof(struct ether_header);
        rem -= sizeof(struct ether_header);

        uint16_t ethertype = ntohs(eth->ether_type);

        if (ethertype == ETHERTYPE_VLAN) {
            if (rem < 4) {
                return;
            }
            metadata_.vlan_id = ntohs(*reinterpret_cast<const uint16_t*>(ptr)) & 0x0FFF;
            ethertype = ntohs(*reinterpret_cast<const uint16_t*>(ptr + 2));
            ptr += 4;
            rem -= 4;
        }

        l3_header_ = ptr;

        if (ethertype == ETHERTYPE_IP) {
            if (rem < sizeof(struct iphdr)) {
                return;
            }
            const auto* ip4 = reinterpret_cast<const struct iphdr*>(ptr);
            size_t ip4_hl = static_cast<size_t>(ip4->ihl) * 4;
            if (ip4_hl < sizeof(struct iphdr) || rem < ip4_hl) {
                return;
            }
            l3_len_ = ip4_hl;
            ptr += ip4_hl;
            rem -= ip4_hl;

            if (ip4->protocol == IPPROTO_TCP) {
                metadata_.l4_proto = L4Protocol::TCP;
            } else if (ip4->protocol == IPPROTO_UDP) {
                metadata_.l4_proto = L4Protocol::UDP;
            } else if (ip4->protocol == IPPROTO_ICMP) {
                metadata_.l4_proto = L4Protocol::ICMP;
            } else {
                metadata_.l4_proto = L4Protocol::Unknown;
            }

            parse_l4(ptr, rem);

        } else if (ethertype == ETHERTYPE_IPV6) {
            if (rem < sizeof(struct ip6_hdr)) {
                return;
            }
            const auto* ip6 = reinterpret_cast<const struct ip6_hdr*>(ptr);
            l3_len_ = sizeof(struct ip6_hdr);
            ptr += sizeof(struct ip6_hdr);
            rem -= sizeof(struct ip6_hdr);

            if (ip6->ip6_ctlun.ip6_un1.ip6_nxt == IPPROTO_TCP) {
                metadata_.l4_proto = L4Protocol::TCP;
            } else if (ip6->ip6_ctlun.ip6_un1.ip6_nxt == IPPROTO_UDP) {
                metadata_.l4_proto = L4Protocol::UDP;
            } else if (ip6->ip6_ctlun.ip6_un1.ip6_nxt == IPPROTO_ICMPV6) {
                metadata_.l4_proto = L4Protocol::ICMPv6;
            } else {
                metadata_.l4_proto = L4Protocol::Unknown;
            }

            parse_l4(ptr, rem);
        }
    }

    void parse_l4(const uint8_t* ptr, size_t rem) noexcept {
        l4_header_ = ptr;

        if (metadata_.l4_proto == L4Protocol::TCP) {
            if (rem < sizeof(struct tcphdr)) {
                l4_len_ = rem;
                payload_ = ptr + rem;
                payload_len_ = 0;
                return;
            }
            const auto* tcp = reinterpret_cast<const struct tcphdr*>(ptr);
            size_t tcp_hlen = static_cast<size_t>(tcp->doff) * 4;
            if (tcp_hlen < sizeof(struct tcphdr)) {
                tcp_hlen = sizeof(struct tcphdr);
            }
            if (rem < tcp_hlen) {
                tcp_hlen = rem;
            }
            l4_len_ = tcp_hlen;
            payload_ = ptr + tcp_hlen;
            payload_len_ = (rem > tcp_hlen) ? (rem - tcp_hlen) : 0;

        } else if (metadata_.l4_proto == L4Protocol::UDP) {
            if (rem < sizeof(struct udphdr)) {
                l4_len_ = rem;
                payload_ = ptr + rem;
                payload_len_ = 0;
                return;
            }
            l4_len_ = sizeof(struct udphdr);
            payload_ = ptr + sizeof(struct udphdr);
            payload_len_ = (rem > sizeof(struct udphdr)) ? (rem - sizeof(struct udphdr)) : 0;

        } else {
            l4_len_ = rem;
            payload_ = ptr + rem;
            payload_len_ = 0;
        }

        compute_flow_hash();
    }

    void compute_flow_hash() noexcept {
        uint32_t h = 2166136261U;
        auto hash_bytes = [&](const void* data, size_t len) {
            const auto* p = reinterpret_cast<const uint8_t*>(data);
            for (size_t i = 0; i < len; ++i) {
                h ^= p[i];
                h *= 16777619U;
            }
        };

        if (metadata_.l4_proto == L4Protocol::TCP || metadata_.l4_proto == L4Protocol::UDP) {
            if (ipv4_header()) {
                const auto* ip4 = ipv4_header();
                hash_bytes(&ip4->saddr, sizeof(ip4->saddr));
                hash_bytes(&ip4->daddr, sizeof(ip4->daddr));
            } else if (ipv6_header()) {
                const auto* ip6 = ipv6_header();
                hash_bytes(&ip6->ip6_src, sizeof(ip6->ip6_src));
                hash_bytes(&ip6->ip6_dst, sizeof(ip6->ip6_dst));
            }

            if (metadata_.l4_proto == L4Protocol::TCP && l4_len_ >= sizeof(struct tcphdr)) {
                const auto* tcp = reinterpret_cast<const struct tcphdr*>(l4_header_);
                hash_bytes(&tcp->source, sizeof(tcp->source));
                hash_bytes(&tcp->dest, sizeof(tcp->dest));
            } else if (metadata_.l4_proto == L4Protocol::UDP && l4_len_ >= sizeof(struct udphdr)) {
                const auto* udp = reinterpret_cast<const struct udphdr*>(l4_header_);
                hash_bytes(&udp->source, sizeof(udp->source));
                hash_bytes(&udp->dest, sizeof(udp->dest));
            }
        } else {
            if (raw_data_.size() > 0) {
                hash_bytes(raw_data_.data(), raw_data_.size() > 64 ? 64 : raw_data_.size());
            }
        }

        metadata_.flow_hash = h;
    }
};

struct FilterStats {
    uint64_t total_packets;
    uint64_t allowed_packets;
    uint64_t dropped_packets;
    uint64_t rate_limited_packets;
    uint64_t bytes_processed;

    constexpr FilterStats() noexcept
        : total_packets(0),
          allowed_packets(0),
          dropped_packets(0),
          rate_limited_packets(0),
          bytes_processed(0) {}

    constexpr void reset() noexcept {
        total_packets = 0;
        allowed_packets = 0;
        dropped_packets = 0;
        rate_limited_packets = 0;
        bytes_processed = 0;
    }
};

} // namespace titan

#endif // TITAN_TYPES_HPP