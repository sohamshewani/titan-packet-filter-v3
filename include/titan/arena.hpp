#ifndef TITAN_ARENA_HPP
#define TITAN_ARENA_HPP

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <atomic>
#include <sys/mman.h>
#include <unistd.h>
#include <iostream>

namespace titan {

constexpr std::size_t CACHE_LINE_SIZE = 64;
constexpr std::size_t HUGE_PAGE_2MB = 2 * 1024 * 1024;
constexpr std::size_t HUGE_PAGE_1GB = 1024 * 1024 * 1024;

inline constexpr std::size_t align_forward(std::size_t ptr, std::size_t alignment) noexcept {
    return (ptr + (alignment - 1)) & ~(alignment - 1);
}

class ArenaBlock {
public:
    ArenaBlock* next;
    std::size_t capacity;
    std::size_t offset;
    alignas(CACHE_LINE_SIZE) char data[];

    static ArenaBlock* create(std::size_t min_size, bool use_huge_pages) noexcept {
        std::size_t total_size = sizeof(ArenaBlock) + min_size;
        void* addr = MAP_FAILED;

        if (use_huge_pages) {
            std::size_t alloc_size = (total_size > HUGE_PAGE_2MB) ? 
                ((total_size + HUGE_PAGE_1GB - 1) & ~(HUGE_PAGE_1GB - 1)) : 
                ((total_size + HUGE_PAGE_2MB - 1) & ~(HUGE_PAGE_2MB - 1));
            
            int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB;
            if (alloc_size >= HUGE_PAGE_1GB) {
                flags |= (30 << MAP_HUGE_SHIFT); // 1GB hugepage designation
            }
            
            addr = mmap(nullptr, alloc_size, PROT_READ | PROT_WRITE, flags, -1, 0);
            if (addr != MAP_FAILED) {
                total_size = alloc_size;
            }
        }

        if (addr == MAP_FAILED) {
            total_size = (total_size + HUGE_PAGE_2MB - 1) & ~(HUGE_PAGE_2MB - 1);
            addr = mmap(nullptr, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (addr == MAP_FAILED) {
                return nullptr;
            }
        }

        ArenaBlock* block = static_cast<ArenaBlock*>(addr);
        block->next = nullptr;
        block->capacity = total_size - sizeof(ArenaBlock);
        block->offset = 0;
        return block;
    }

    void destroy() noexcept {
        std::size_t total_size = sizeof(ArenaBlock) + capacity;
        munmap(this, total_size);
    }
};

class Arena {
private:
    ArenaBlock* primary_head_;
    ArenaBlock* backup_head_;
    bool use_backup_;
    std::size_t default_block_size_;
    bool use_huge_pages_;
    std::atomic<uint64_t> exhaustion_counter_;

    ArenaBlock* allocate_block(std::size_t size) noexcept {
        std::size_t req_size = (size > default_block_size_) ? size : default_block_size_;
        return ArenaBlock::create(req_size, use_huge_pages_);
    }

    void free_block_chain(ArenaBlock* block) noexcept {
        while (block != nullptr) {
            ArenaBlock* next = block->next;
            block->destroy();
            block = next;
        }
    }

public:
    explicit Arena(std::size_t default_block_size = HUGE_PAGE_2MB, bool use_huge_pages = true) noexcept
        : primary_head_(nullptr),
          backup_head_(nullptr),
          use_backup_(false),
          default_block_size_(default_block_size),
          use_huge_pages_(use_huge_pages),
          exhaustion_counter_(0) {
        primary_head_ = allocate_block(default_block_size_);
        backup_head_ = allocate_block(default_block_size_);
    }

    ~Arena() noexcept {
        free_block_chain(primary_head_);
        free_block_chain(backup_head_);
    }

    Arena(const Arena&) = delete;
    Arena& operator=(const Arena&) = delete;
    Arena(Arena&&) noexcept = delete;
    Arena& operator=(Arena&&) noexcept = delete;

    [[nodiscard]] void* allocate(std::size_t size, std::size_t alignment = CACHE_LINE_SIZE) noexcept {
        if (size == 0) {
            return nullptr;
        }

        ArenaBlock*& current_head = use_backup_ ? backup_head_ : primary_head_;

        if (current_head == nullptr) {
            current_head = allocate_block(size + alignment);
            if (current_head == nullptr) {
                if (!use_backup_) {
                    use_backup_ = true;
                    exhaustion_counter_.fetch_add(1, std::memory_order_relaxed);
                    std::cerr << "[CRITICAL] TITAN_ARENA_EXHAUSTION: Primary arena exhausted. Failing over to backup arena. Metric ID: 0xA1001" << std::endl;
                    current_head = backup_head_;
                } else {
                    std::cerr << "[FATAL] TITAN_ARENA_EXHAUSTION: Backup arena also exhausted. Aborting allocation. Metric ID: 0xA1002" << std::endl;
                    return nullptr;
                }
            }
        }

        std::size_t current_address = reinterpret_cast<std::size_t>(current_head->data + current_head->offset);
        std::size_t aligned_address = align_forward(current_address, alignment);
        std::size_t padding = aligned_address - current_address;
        std::size_t required_space = size + padding;

        if (current_head->offset + required_space > current_head->capacity) {
            ArenaBlock* new_block = allocate_block(size + alignment);
            if (new_block == nullptr) {
                if (!use_backup_) {
                    use_backup_ = true;
                    exhaustion_counter_.fetch_add(1, std::memory_order_relaxed);
                    std::cerr << "[CRITICAL] TITAN_ARENA_EXHAUSTION: Primary block chain exhausted. Failing over to backup arena. Metric ID: 0xA1003" << std::endl;
                    current_head = backup_head_;
                } else {
                    std::cerr << "[FATAL] TITAN_ARENA_EXHAUSTION: Secondary fallback failed. Out of memory. Metric ID: 0xA1004" << std::endl;
                    return nullptr;
                }
                
                if (current_head != nullptr) {
                    current_address = reinterpret_cast<std::size_t>(current_head->data + current_head->offset);
                    aligned_address = align_forward(current_address, alignment);
                    padding = aligned_address - current_address;
                    required_space = size + padding;
                }
            } else {
                new_block->next = current_head;
                current_head = new_block;
                current_address = reinterpret_cast<std::size_t>(current_head->data + current_head->offset);
                aligned_address = align_forward(current_address, alignment);
                padding = aligned_address - current_address;
                required_space = size + padding;
            }

            if (current_head->offset + required_space > current_head->capacity) {
                return nullptr;
            }
        }

        void* ptr = reinterpret_cast<void*>(aligned_address);
        current_head->offset += required_space;
        return ptr;
    }

    template <typename T, typename... Args>
    [[nodiscard]] T* create(Args&&... args) noexcept {
        void* mem = allocate(sizeof(T), alignof(T));
        if (mem == nullptr) {
            return nullptr;
        }
        return ::new (mem) T(std::forward<Args>(args)...);
    }

    void reset() noexcept {
        ArenaBlock* block = primary_head_;
        while (block != nullptr) {
            block->offset = 0;
            block = block->next;
        }

        ArenaBlock* backup = backup_head_;
        while (backup != nullptr) {
            backup->offset = 0;
            backup = backup->next;
        }

        use_backup_ = false;
    }

    [[nodiscard]] uint64_t get_exhaustion_count() const noexcept {
        return exhaustion_counter_.load(std::memory_order_relaxed);
    }
};

} // namespace titan

#endif // TITAN_ARENA_HPP