# titan-packet-filter
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![CI](https://github.com/sohamshewani/titan-packet-filter/actions/workflows/ci.yml/badge.svg)](https://github.com/sohamshewani/titan-packet-filter/actions) [![Security: Hardened](https://img.shields.io/badge/Security-Hardened-blue.svg)](https://github.com/sohamshewani/titan-packet-filter) [![Stars](https://img.shields.io/github.com/sohamshewani/titan-packet-filter?style=flat)](https://github.com/sohamshewani/titan-packet-filter)

## Executive Summary & Problem Space

Modern enterprise networking infrastructures operate under severe throughput constraints, processing tens of millions of packets per second (Mpps) per core. Traditional packet filtering architectures fail to scale under these conditions due to fundamental hardware and software bottlenecks:

1. **Heap Allocation Overhead:** Standard networking stacks invoke system allocators (`malloc`/`free`) per packet or per connection frame, creating severe lock contention and memory fragmentation in multi-threaded runtime environments.
2. **Lock Contention:** Shared data structures protected by coarse-grained mutexes introduce cache-line bouncing and thread serialization, scaling negatively with core count.
3. **Data Path Latency Spikes:** Garbage collection pauses, unpredicatable cache eviction patterns, and context switching introduce tail latency spikes (P99/P99.9) that violate Service Level Agreements (SLAs) in high-frequency trading and carrier-grade edge gateways.

`titan-packet-filter` is an enterprise-grade, ultra-low-latency packet processing and filtering engine written in modern C++ (C++20). It bypasses traditional OS kernel bottlenecks by utilizing a lockless ring buffer architecture, zero-allocation arena allocators, deterministic flow control, and vectorized execution engines. Designed for multi-core NUMA systems, `titan-packet-filter` achieves predictable line-rate performance with microsecond-scale tail latencies.

---

## Structural ASCII Architecture / Dataflow Diagram

The system architecture cleanly separates packet ingestion, zero-allocation memory staging, core filtering logic, and asynchronous telemetry loops.

```
 +-----------------------------------------------------------------------+
 |                       Network Interface / Driver                      |
 +-----------------------------------------------------------------------+
                                    |
                                    v (Raw Packet Ingress)
 +-----------------------------------------------------------------------+
 |                          include/titan/poll_loop.hpp                  |
 |  +-----------------------------------------------------------------+  |
 |  |                Non-blocking Epoll/Poll Dispatcher               |  |
 |  +-----------------------------------------------------------------+  |
 +-----------------------------------------------------------------------+
                                    |
                                    v
 +-----------------------------------------------------------------------+
 |                       include/titan/ring_buffer.hpp                   |
 |  +-----------------------------------------------------------------+  |
 |  |            Lockless Producer-Consumer SPSC/MPSC Ring            |  |
 |  +-----------------------------------------------------------------+  |
 +-----------------------------------------------------------------------+
                                    |
                                    v
 +-----------------------------------------------------------------------+
 |                     include/titan/filter_engine.hpp                   |
 |  +-----------------------------------------------------------------+  |
 |  |                Vectorized Rule Matching & Parsing               |  |
 |  +-----------------------------------------------------------------+  |
 |            |                                           |
 |            v (Memory Allocation)                       v (Flow Control)
 |  +-----------------------------+             +------------------------+
 |  |  include/titan/arena.hpp    |             | include/titan/flow...  |
 |  |  Bump-Pointer Region Alloc  |             | Rate Limiting & Backp  |
 |  +-----------------------------+             +------------------------+
 |            |                                           |
 +------------+-------------------------------------------+
              |
              v (Processed Packet Output / Drop / Alert)
 +-----------------------------------------------------------------------+
 |                        include/titan/types.hpp                        |
 |            Strongly-Typed Identifiers, Metadata & Enums               |
 +-----------------------------------------------------------------------+
```

---

## Concurrency Model & Memory Invariants

`titan-packet-filter` implements a strict thread-per-core pin model designed to eliminate lock contention on hot data paths.

* **Lockless SPSC/MPSC Ring Buffers (`include/titan/ring_buffer.hpp`):** Communication between ingress threads and worker pools utilizes memory-ordered atomic operations (`std::memory_order_acquire` and `std::memory_order_release`). Tail and head pointers are cache-aligned (`alignas(64)`) to prevent false sharing across CPU cores.
* **Bump-Pointer Arena Allocation (`include/titan/arena.hpp`):** To avoid dynamic heap fragmentation, packet metadata and intermediate state structures are provisioned via thread-local arena allocators. Memory is released in bulk reset operations, guaranteeing $\mathcal{O}(1)$ allocation complexity with zero calls to `malloc` during steady-state packet processing.
* **Deterministic Flow Control (`include/titan/flow_control.hpp`):** Token bucket and leaky bucket primitives manage rate limiting per flow without mutex locks, employing atomic CAS (Compare-And-Swap) loops to safely update state across concurrent evaluation workers.
* **Memory Invariants:**
  1. No raw pointers are retained across ring buffer boundaries; all payloads adhere to RAII and smart-pointer encapsulation where ownership transfer is explicit.
  2. Thread-safety annotations and const-correctness are enforced statically across all engine components.

---

## Performance Characteristics & Algorithmic Complexity Table

| Operation | Component | Big-O Time Complexity | Big-O Space Complexity | Estimated Latency (P50 / P99) |
| :--- | :--- | :--- | :--- | :--- |
| **Packet Push** | `ring_buffer.hpp` | $\mathcal{O}(1)$ | $\mathcal{O}(N)$ fixed buffer | $45\text{ns}$ / $120\text{ns}$ |
| **Packet Pop** | `ring_buffer.hpp` | $\mathcal{O}(1)$ | $\mathcal{O}(1)$ | $30\text{ns}$ / $95\text{ns}$ |
| **Arena Allocation** | `arena.hpp` | $\mathcal{O}(1)$ | $\mathcal{O}(M)$ arena pool | $5\text{ns}$ / $12\text{ns}$ |
| **Rule Matching** | `filter_engine.hpp` | $\mathcal{O}(R)$ ($R = \text{rules}$) | $\mathcal{O}(1)$ auxiliary memory | $120\text{ns}$ / $340\text{ns}$ |
| **Flow Rate Check** | `flow_control.hpp` | $\mathcal{O}(1)$ | $\mathcal{O}(F)$ active flows | $15\text{ns}$ / $40\text{ns}$ |
| **Poll Loop Event Dispatch** | `poll_loop.hpp` | $\mathcal{O}(E)$ ($E = \text{events}$) | $\mathcal{O}(1)$ | $250\text{ns}$ / $850\text{ns}$ |

---

## Security Architecture & Threat Model

`titan-packet-filter` is engineered for zero-trust, high-exposure network boundaries where systems are subjected to malformed payloads, denial-of-service vectors, and memory corruption attempts.

* **Input Boundary Sanitization:** All incoming byte streams parsed via `filter_engine.hpp` pass through strict bounds checking and header validation masks before processing. Malformed layers trigger immediate, safe packet drops without destabilizing worker execution.
* **Memory Safety & Bounds Verification:** Strict C++20 typing (`include/titan/types.hpp`) avoids unsafe C-style pointer arithmetic. Automated test suites (`tests/test_invariants.cpp`) run continuous invariant checks verifying buffer boundaries, integer overflow protections, and memory alignment constraints.
* **Mitigated Threat Vectors:**
  * *Buffer Overflows:* Prevented via explicit span views and fixed-capacity ring buffers.
  * *Resource Exhaustion (DoS):* Bounded arena pools and per-flow rate limits (`flow_control.hpp`) reject memory starvation and flooding attacks.
  * *Race Conditions:* Validated through ThreadSanitizer (TSan) pipelines enforced in CI/CD workflows.

---

## Build, Verification & Benchmarking Recipes

### Prerequisites
* GCC 11+ or Clang 13+ with C++20 support
* GNU Make 4.0+
* POSIX-compliant environment (Linux recommended for full poll loop and ring buffer performance characteristics)

### Build Instructions
To compile the library, invariant test suites, and micro-benchmarks in release mode with optimizations:
```bash
make clean
make all
```

### Running Invariant Tests
Execute the comprehensive test harness to verify memory safety, ring buffer synchronization, and rule matching logic:
```bash
make test
```
*Expected Output:* All assertion checks in `tests/test_invariants.cpp` pass successfully with zero memory leaks or data races detected.

### Executing Micro-Benchmarks
Run the performance benchmark suite (`benchmarks/bench_engine.cpp`) to profile packet filter throughput and latency profiles:
```bash
make bench
```

---

## Repository Structure Overview

* `include/titan/types.hpp` — Core type definitions, error codes, and packet metadata structures.
* `include/titan/arena.hpp` — High-performance bump-pointer memory arena.
* `include/titan/ring_buffer.hpp` — Lockless, cache-aligned single-producer single-consumer ring buffer.
* `include/titan/flow_control.hpp` — Lock-free rate limiting and connection tracking.
* `include/titan/filter_engine.hpp` — Core packet inspection and rule evaluation engine.
* `include/titan/poll_loop.hpp` — Event-driven I/O polling architecture.
* `tests/test_invariants.cpp` — System invariant verification and unit testing suite.
* `benchmarks/bench_engine.cpp` — Performance measurement and latency profiling harnesses.
* `Makefile` — Build automation configuration.

---

## License

Distributed under the MIT License. See [LICENSE](https://opensource.org/licenses/MIT) for details.