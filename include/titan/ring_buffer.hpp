#ifndef TITAN_RING_BUFFER_HPP
#define TITAN_RING_BUFFER_HPP

#include <atomic>
#include <cstdint>
#include <cstddef>
#include <optional>
#include <new>
#include <type_traits>

namespace titan {

template <typename T, std::size_t Capacity>
class SPSCQueue {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be a power of two for bitwise masking.");
    static_assert(Capacity > 0, "Capacity must be greater than zero.");

public:
    SPSCQueue() : head_(0), tail_(0) {}

    ~SPSCQueue() {
        while (pop().has_value()) {
            // Drain remaining elements to invoke destructors safely
        }
    }

    SPSCQueue(const SPSCQueue&) = delete;
    SPSCQueue& operator=(const SPSCQueue&) = delete;
    SPSCQueue(SPSCQueue&&) = delete;
    SPSCQueue& operator=(SPSCQueue&&) = delete;

    template <typename... Args>
    bool emplace(Args&&... args) {
        const std::size_t current_tail = tail_.load(std::memory_order_relaxed);
        const std::size_t current_head = head_.load(std::memory_order_acquire);

        if ((current_tail - current_head) >= Capacity) {
            return false; // Ring buffer saturated (Drop-tail policy point)
        }

        ::new (static_cast<void*>(&buffer_[current_tail & Mask].storage)) T(std::forward<Args>(args)...);
        tail_.store(current_tail + 1, std::memory_order_release);
        return true;
    }

    bool push(const T& item) {
        return emplace(item);
    }

    bool push(T&& item) {
        return emplace(std::move(item));
    }

    std::optional<T> pop() {
        const std::size_t current_head = head_.load(std::memory_order_relaxed);
        const std::size_t current_tail = tail_.load(std::memory_order_acquire);

        if (current_head == current_tail) {
            return std::nullopt; // Ring buffer empty
        }

        T* item_ptr = reinterpret_cast<T*>(&buffer_[current_head & Mask].storage);
        T item = std::move(*item_ptr);
        item_ptr->~T();

        head_.store(current_head + 1, std::memory_order_release);
        return item;
    }

    [[nodiscard]] bool empty() const {
        return head_.load(std::memory_order_acquire) == tail_.load(std::memory_order_acquire);
    }

    [[nodiscard]] bool full() const {
        const std::size_t current_tail = tail_.load(std::memory_order_acquire);
        const std::size_t current_head = head_.load(std::memory_order_acquire);
        return (current_tail - current_head) >= Capacity;
    }

    [[nodiscard]] std::size_t size() const {
        std::size_t current_tail = tail_.load(std::memory_order_acquire);
        std::size_t current_head = head_.load(std::memory_order_acquire);
        if (current_tail >= current_head) {
            return current_tail - current_head;
        }
        return 0;
    }

    [[nodiscard]] constexpr std::size_t capacity() const {
        return Capacity;
    }

private:
    union Node {
        alignas(alignof(T)) char storage[sizeof(T)];
        Node() {}
        ~Node() {}
    };

    static constexpr std::size_t Mask = Capacity - 1;

    alignas(64) std::atomic<std::size_t> head_;
    alignas(64) std::atomic<std::size_t> tail_;
    alignas(64) Node buffer_[Capacity];
};

template <typename T, std::size_t Capacity>
class MPMCQueue {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be a power of two for bitwise masking.");
    static_assert(Capacity > 0, "Capacity must be greater than zero.");

public:
    MPMCQueue() : head_(0), tail_(0) {
        for (std::size_t i = 0; i < Capacity; ++i) {
            buffer_[i].sequence.store(i, std::memory_order_relaxed);
        }
    }

    ~MPMCQueue() {
        T dummy;
        while (pop(dummy)) {
            // Drain elements to ensure proper destruction
        }
    }

    MPMCQueue(const MPMCQueue&) = delete;
    MPMCQueue& operator=(const MPMCQueue&) = delete;
    MPMCQueue(MPMCQueue&&) = delete;
    MPMCQueue& operator=(MPMCQueue&&) = delete;

    template <typename... Args>
    bool emplace(Args&&... args) {
        Cell* cell;
        std::size_t current_tail = tail_.load(std::memory_order_relaxed);
        
        for (;;) {
            cell = &buffer_[current_tail & Mask];
            std::size_t seq = cell->sequence.load(std::memory_order_acquire);
            intptr_t dif = static_cast<intptr_t>(seq) - static_cast<intptr_t>(current_tail);

            if (dif == 0) {
                if (tail_.compare_exchange_weak(current_tail, current_tail + 1,
                                                std::memory_order_relaxed,
                                                std::memory_order_relaxed)) {
                    break;
                }
            } else if (dif < 0) {
                return false; // Queue is full (Drop-tail saturation policy)
            } else {
                current_tail = tail_.load(std::memory_order_relaxed);
            }
        }

        ::new (static_cast<void*>(&cell->storage)) T(std::forward<Args>(args)...);
        cell->sequence.store(current_tail + 1, std::memory_order_release);
        return true;
    }

    bool push(const T& item) {
        return emplace(item);
    }

    bool push(T&& item) {
        return emplace(std::move(item));
    }

    bool pop(T& item) {
        Cell* cell;
        std::size_t current_head = head_.load(std::memory_order_relaxed);

        for (;;) {
            cell = &buffer_[current_head & Mask];
            std::size_t seq = cell->sequence.load(std::memory_order_acquire);
            intptr_t dif = static_cast<intptr_t>(seq) - static_cast<intptr_t>(current_head + 1);

            if (dif == 0) {
                if (head_.compare_exchange_weak(current_head, current_head + 1,
                                                std::memory_order_relaxed,
                                                std::memory_order_relaxed)) {
                    break;
                }
            } else if (dif < 0) {
                return false; // Queue is empty
            } else {
                current_head = head_.load(std::memory_order_relaxed);
            }
        }

        T* item_ptr = reinterpret_cast<T*>(&cell->storage);
        item = std::move(*item_ptr);
        item_ptr->~T();

        cell->sequence.store(current_head + Mask + 1, std::memory_order_release);
        return true;
    }

    [[nodiscard]] std::size_t size() const {
        std::size_t current_tail = tail_.load(std::memory_order_acquire);
        std::size_t current_head = head_.load(std::memory_order_acquire);
        if (current_tail >= current_head) {
            return current_tail - current_head;
        }
        return 0;
    }

    [[nodiscard]] bool empty() const {
        return size() == 0;
    }

    [[nodiscard]] constexpr std::size_t capacity() const {
        return Capacity;
    }

private:
    struct Cell {
        alignas(alignof(T)) char storage[sizeof(T)];
        std::atomic<std::size_t> sequence;
        Cell() {}
        ~Cell() {}
    };

    static constexpr std::size_t Mask = Capacity - 1;

    alignas(64) std::atomic<std::size_t> head_;
    alignas(64) std::atomic<std::size_t> tail_;
    Cell buffer_[Capacity];
};

} // namespace titan

#endif // TITAN_RING_BUFFER_HPP