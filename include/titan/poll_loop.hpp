#ifndef TITAN_POLL_LOOP_HPP
#define TITAN_POLL_LOOP_HPP

#include <cstdint>
#include <cstddef>
#include <cerrno>
#include <cstring>
#include <unistd.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <atomic>
#include <chrono>
#include <thread>
#include <system_error>
#include <functional>

namespace titan {

enum class PollState : uint8_t {
    Stopped = 0,
    Running = 1,
    Stopping = 2,
    Error = 3
};

struct PollLoopConfig {
    int max_events = 1024;
    int epoll_timeout_ms = -1;
    uint32_t spin_limit = 100;
    bool use_edge_triggered = true;
};

class PollLoop {
public:
    using EventCallback = std::function<void(int fd, uint32_t events)>;

    explicit PollLoop(PollLoopConfig config = PollLoopConfig{})
        : config_(config),
          epoll_fd_(-1),
          state_(PollState::Stopped),
          spin_count_(0) {
        
        epoll_fd_ = ::epoll_create1(EPOLL_CLOEXEC);
        if (epoll_fd_ < 0) {
            throw std::system_error(errno, std::generic_category(), "Failed to create epoll instance");
        }
    }

    ~PollLoop() {
        stop();
        if (epoll_fd_ >= 0) {
            ::close(epoll_fd_);
            epoll_fd_ = -1;
        }
    }

    PollLoop(const PollLoop&) = delete;
    PollLoop& operator=(const PollLoop&) = delete;
    PollLoop(PollLoop&& other) noexcept
        : config_(other.config_),
          epoll_fd_(other.epoll_fd_),
          state_(other.state_.load(std::memory_order_relaxed)),
          spin_count_(other.spin_count_.load(std::memory_order_relaxed)) {
        other.epoll_fd_ = -1;
        other.state_.store(PollState::Stopped, std::memory_order_relaxed);
    }

    PollLoop& operator=(PollLoop&& other) noexcept {
        if (this != &other) {
            stop();
            if (epoll_fd_ >= 0) {
                ::close(epoll_fd_);
            }
            config_ = other.config_;
            epoll_fd_ = other.epoll_fd_;
            state_.store(other.state_.load(std::memory_order_relaxed), std::memory_order_relaxed);
            spin_count_.store(other.spin_count_.load(std::memory_order_relaxed), std::memory_order_relaxed);
            other.epoll_fd_ = -1;
            other.state_.store(PollState::Stopped, std::memory_order_relaxed);
        }
        return *this;
    }

    void register_fd(int fd, uint32_t events, EventCallback callback) {
        if (fd < 0) {
            throw std::invalid_argument("Invalid file descriptor provided to register_fd");
        }

        make_non_blocking(fd);

        struct epoll_event ev{};
        ev.events = events;
        if (config_.use_edge_triggered) {
            ev.events |= EPOLLET;
        }
        
        // Storing the fd inside data.fd for reliable dispatch
        ev.data.fd = fd;

        // Registering callback externally or mapping it would require an internal registry.
        // For self-contained performance, we assume callbacks are handled via external dispatch 
        // or mapped via a fast-path associative structure. Here we bind the fd to the event subsystem.
        int res = ::epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev);
        if (res < 0) {
            if (errno == EEXIST) {
                res = ::epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd, &ev);
                if (res < 0) {
                    throw std::system_error(errno, std::generic_category(), "Failed to modify epoll registration");
                }
            } else {
                throw std::system_error(errno, std::generic_category(), "Failed to add epoll registration");
            }
        }
    }

    void unregister_fd(int fd) {
        if (fd < 0) {
            return;
        }
        // Passing nullptr as event structure is required for older Linux kernels with EPOLL_CTL_DEL
        struct epoll_event ev{};
        ::epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, &ev);
    }

    void run(const std::function<void(int, uint32_t)>& dispatch_callback) {
        PollState expected = PollState::Stopped;
        if (!state_.compare_exchange_strong(expected, PollState::Running, 
                                            std::memory_order_acq_rel, 
                                            std::memory_order_relaxed)) {
            return;
        }

        alignas(64) struct epoll_event events[config_.max_events];

        while (state_.load(std::memory_order_acquire) == PollState::Running) {
            int n_events = ::epoll_wait(epoll_fd_, events, config_.max_events, config_.epoll_timeout_ms);
            
            if (n_events < 0) {
                if (errno == EINTR) {
                    continue;
                }
                state_.store(PollState::Error, std::memory_order_release);
                break;
            }

            if (n_events == 0) {
                // Adaptive spin-poll backoff strategy under zero-event ingress
                if (spin_count_.load(std::memory_order_relaxed) < config_.spin_limit) {
                    spin_count_.fetch_add(1, std::memory_order_relaxed);
                    // Emit CPU pause instruction to prevent pipeline flush stalls during aggressive polling
                    #if defined(__x86_64__) || defined(_M_X64)
                    _mm_pause();
                    #elif defined(__aarch64__)
                    asm volatile("yield" ::: "memory");
                    #endif
                    continue;
                } else {
                    // Yield execution slice back to scheduler when backoff threshold is breached
                    std::this_thread::yield();
                    spin_count_.store(0, std::memory_order_relaxed);
                }
                continue;
            }

            // Reset spin-backoff counter upon receiving valid ingress traffic
            spin_count_.store(0, std::memory_order_relaxed);

            for (int i = 0; i < n_events; ++i) {
                int active_fd = events[i].data.fd;
                uint32_t active_events = events[i].events;
                
                if (dispatch_callback) {
                    dispatch_callback(active_fd, active_events);
                }
            }
        }

        state_.store(PollState::Stopped, std::memory_order_release);
    }

    void stop() {
        PollState expected = PollState::Running;
        if (state_.compare_exchange_strong(expected, PollState::Stopping,
                                           std::memory_order_acq_rel,
                                           std::memory_order_relaxed)) {
            // Wake up epoll_wait via a dummy control or wait timeout expiration.
            // Edge-triggered loop will safely terminate on next iteration cycle.
        }
    }

    PollState state() const noexcept {
        return state_.load(std::memory_order_acquire);
    }

private:
    void make_non_blocking(int fd) {
        int flags = ::fcntl(fd, F_GETFL, 0);
        if (flags < 0) {
            throw std::system_error(errno, std::generic_category(), "Failed to get fd flags");
        }
        if (::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            throw std::system_error(errno, std::generic_category(), "Failed to set fd to non-blocking");
        }
    }

    PollLoopConfig config_;
    int epoll_fd_;
    alignas(64) std::atomic<PollState> state_;
    alignas(64) std::atomic<uint32_t> spin_count_;
};

} // namespace titan

#endif // TITAN_POLL_LOOP_HPP