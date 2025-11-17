#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdbool.h>

#define USE_MMAP 1          // Set to 1 for mmap(), 0 for sbrk()
#define ALIGNMENT 16        // Memory alignment (16 bytes for x86-64)
#define MIN_BLOCK_SIZE 32   // Minimum block size
#define MMAP_THRESHOLD 128 * 1024  // Use mmap for allocations > 128KB

typedef enum {
    FIRST_FIT,
    BEST_FIT,
    NEXT_FIT
} alloc_strategy_t;

static alloc_strategy_t current_strategy = FIRST_FIT;

typedef struct block_header {
    size_t size;                    // Size of block (including header)
    bool is_free;                   // Free flag
    struct block_header *next;      // Next block in free list
    struct block_header *prev;      // Previous block in free list
    bool is_mmap;                   // Was allocated with mmap?
} block_header_t;

/* Global variables YAYAYAYYAY YIPPY AYAYYAYAYYYYAYYYAYYYYA :\ */
static block_header_t *free_list_head = NULL;
static block_header_t *last_allocated = NULL;  // For next-fit

static inline size_t align_size(size_t size) {
    return (size + ALIGNMENT - 1) & ~(ALIGNMENT - 1);
}

static inline void *block_to_ptr(block_header_t *block) {
    return (void *)(block + 1);
}

static inline block_header_t *ptr_to_block(void *ptr) {
    return ((block_header_t *)ptr) - 1;
}

/* Request memory from OS using sbrk() */
static block_header_t *request_space_sbrk(size_t size) {
    block_header_t *block;
    void *request;
    
    size = align_size(size + sizeof(block_header_t));
    
    request = sbrk(size);
    if (request == (void *)-1) {
        return NULL;  // sbrk failed
    }
    
    block = (block_header_t *)request;
    block->size = size;
    block->is_free = false;
    block->next = NULL;
    block->prev = NULL;
    block->is_mmap = false;
    
    return block;
}

/* request memory from OS using mmap() */
static block_header_t *request_space_mmap(size_t size) {
    size_t total_size = align_size(size + sizeof(block_header_t));
    
    void *ptr = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (ptr == MAP_FAILED) {
        return NULL;
    }
    
    block_header_t *block = (block_header_t *)ptr;
    block->size = total_size;
    block->is_free = false;
    block->next = NULL;
    block->prev = NULL;
    block->is_mmap = true;
    
    return block;
}

static void add_to_free_list(block_header_t *block) {
    block->is_free = true;
    
    if (free_list_head == NULL) {
        free_list_head = block;
        block->next = NULL;
        block->prev = NULL;
    } else {
        block->next = free_list_head;
        block->prev = NULL;
        if (free_list_head) {
            free_list_head->prev = block;
        }
        free_list_head = block;
    }
}

static void remove_from_free_list(block_header_t *block) {
    if (block->prev) {
        block->prev->next = block->next;
    } else {
        free_list_head = block->next;
    }
    
    if (block->next) {
        block->next->prev = block->prev;
    }
    
    block->next = NULL;
    block->prev = NULL;
}

static block_header_t *coalesce(block_header_t *block) {
    if (block->is_mmap) {
        return block;  // Can't coalesce mmap blocks
    }
    
    block_header_t *current = free_list_head;
    
    while (current != NULL) {
        if (current->is_mmap) {
            current = current->next;
            continue;
        }
        
        void *current_end = (char *)current + current->size;
        void *block_end = (char *)block + block->size;
        
        // Coalesce with next block
        if (current_end == (void *)block) {
            remove_from_free_list(block);
            current->size += block->size;
            return coalesce(current);  // Recursively coalesce
        }
        
        // Coalesce with previous block
        if (block_end == (void *)current) {
            remove_from_free_list(current);
            block->size += current->size;
            return coalesce(block);  // Recursively coalesce
        }
        
        current = current->next;
    }
    
    return block;
}

/* Split block if it's larger than needed */
static void split_block(block_header_t *block, size_t size) {
    size = align_size(size + sizeof(block_header_t));
    
    if (block->size >= size + sizeof(block_header_t) + MIN_BLOCK_SIZE) {
        block_header_t *new_block = (block_header_t *)((char *)block + size);
        new_block->size = block->size - size;
        new_block->is_mmap = false;
        
        block->size = size;
        
        add_to_free_list(new_block);
    }
}

static block_header_t *find_first_fit(size_t size) {
    block_header_t *current = free_list_head;
    
    while (current != NULL) {
        if (current->is_free && current->size >= size) {
            return current;
        }
        current = current->next;
    }
    
    return NULL;
}

static block_header_t *find_best_fit(size_t size) {
    block_header_t *current = free_list_head;
    block_header_t *best = NULL;
    size_t best_size = SIZE_MAX;
    
    while (current != NULL) {
        if (current->is_free && current->size >= size) {
            if (current->size < best_size) {
                best = current;
                best_size = current->size;
            }
        }
        current = current->next;
    }
    
    return best;
}

static block_header_t *find_next_fit(size_t size) {
    block_header_t *current = last_allocated ? last_allocated : free_list_head;
    block_header_t *start = current;
    
    if (current == NULL) {
        return NULL;
    }
    
    do {
        if (current->is_free && current->size >= size) {
            last_allocated = current;
            return current;
        }
        
        current = current->next;
        if (current == NULL) {
            current = free_list_head;
        }
    } while (current != start);
    
    return NULL;
}

static block_header_t *find_free_block(size_t size) {
    switch (current_strategy) {
        case FIRST_FIT:
            return find_first_fit(size);
        case BEST_FIT:
            return find_best_fit(size);
        case NEXT_FIT:
            return find_next_fit(size);
        default:
            return find_first_fit(size);
    }
}

void *tiny_alloc(size_t size) {
    if (size == 0) {
        return NULL;
    }
    
    size = align_size(size);
    size_t total_size = size + sizeof(block_header_t);
    
    // For large allocations, use mmap
    if (USE_MMAP && size >= MMAP_THRESHOLD) {
        block_header_t *block = request_space_mmap(size);
        if (block == NULL) {
            return NULL;
        }
        return block_to_ptr(block);
    }
    
    // Try to find a free block
    block_header_t *block = find_free_block(total_size);
    
    if (block != NULL) {
        // Found a free block
        remove_from_free_list(block);
        split_block(block, size);
        block->is_free = false;
        last_allocated = block;
        return block_to_ptr(block);
    }
    
    // No block found, request more memory
#if USE_MMAP
    block = request_space_mmap(size);
#else
    block = request_space_sbrk(size);
#endif
    
    if (block == NULL) {
        return NULL;
    }
    
    last_allocated = block;
    return block_to_ptr(block);
}

void tiny_free(void *ptr) {
    if (ptr == NULL) {
        return;
    }
    
    block_header_t *block = ptr_to_block(ptr);
    
    if (block->is_mmap) {
        munmap(block, block->size);
        return;
    }
    
    add_to_free_list(block);
    coalesce(block);
}

void *tiny_calloc(size_t nmemb, size_t size) {
    size_t total = nmemb * size;
    void *ptr = tiny_alloc(total);
    
    if (ptr) {
        memset(ptr, 0, total);
    }
    
    return ptr;
}

void *tiny_realloc(void *ptr, size_t size) {
    if (ptr == NULL) {
        return tiny_alloc(size);
    }
    
    if (size == 0) {
        tiny_free(ptr);
        return NULL;
    }
    
    block_header_t *block = ptr_to_block(ptr);
    
    if (block->size - sizeof(block_header_t) >= size) {
        return ptr;  // Current block should be large enough
    }
    
    void *new_ptr = tiny_alloc(size);
    if (new_ptr == NULL) {
        return NULL;
    }
    
    size_t copy_size = block->size - sizeof(block_header_t);
    if (copy_size > size) {
        copy_size = size;
    }
    
    memcpy(new_ptr, ptr, copy_size);
    tiny_free(ptr);
    
    return new_ptr;
}

void tiny_set_strategy(alloc_strategy_t strategy) {
    current_strategy = strategy;
}

void tiny_print_stats(void) {
    printf("\n=== Tiny Statistics ===\n");
    printf("Strategy: ");
    switch (current_strategy) {
        case FIRST_FIT: printf("First-Fit\n"); break;
        case BEST_FIT: printf("Best-Fit\n"); break;
        case NEXT_FIT: printf("Next-Fit\n"); break;
    }
    
    printf("\nFree List:\n");
    block_header_t *current = free_list_head;
    int count = 0;
    size_t total_free = 0;
    
    while (current != NULL) {
        printf("  Block %d: size=%zu bytes, mmap=%d\n", 
               count++, current->size, current->is_mmap);
        total_free += current->size;
        current = current->next;
    }
    
    printf("\nTotal free blocks: %d\n", count);
    printf("Total free memory: %zu bytes\n", total_free);
    printf("=======================\n\n");
}

/* Test program*/
int main(void) {
    printf("Tiny Memory Allocator Test\n");
    printf("Using %s for memory allocation\n\n", USE_MMAP ? "mmap()" : "sbrk()");
    
    printf("--- Testing FIRST-FIT ---\n");
    tiny_set_strategy(FIRST_FIT);
    
    char *p1 = tiny_alloc(100);
    char *p2 = tiny_alloc(200);
    char *p3 = tiny_alloc(150);
    
    strcpy(p1, "Hello, World!");
    printf("p1: %s\n", p1);
    
    tiny_free(p2);  // Free middle block
    tiny_print_stats();
    
    char *p4 = tiny_alloc(50);  // Should use freed p2 space
    tiny_print_stats();
    
    tiny_free(p1);
    tiny_free(p3);
    tiny_free(p4);
    
    printf("\n--- Testing BEST-FIT ---\n");
    tiny_set_strategy(BEST_FIT);
    
    char *b1 = tiny_alloc(100);
    char *b2 = tiny_alloc(500);
    char *b3 = tiny_alloc(200);
    
    tiny_free(b1);
    tiny_free(b3);
    
    char *b4 = tiny_alloc(150);  // should use b3 (best fit)
    tiny_print_stats();
    
    tiny_free(b2);
    tiny_free(b4);
    
    printf("\n--- Testing COALESCING ---\n");
    char *c1 = tiny_alloc(100);
    char *c2 = tiny_alloc(100);
    char *c3 = tiny_alloc(100);
    
    printf("Before freeing:\n");
    tiny_print_stats();
    
    tiny_free(c1);
    tiny_free(c3);
    tiny_free(c2);  // Should coalesce all three :3
    
    printf("After freeing (should coalesce):\n");
    tiny_print_stats();
    
    printf("All tests completed!\n");
    
    return 0;
}
