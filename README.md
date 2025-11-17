# Tiny (`malloc`-like Clone)

A memory allocator with free-list management and multiple allocation strategies.

## Features

- Free-list management with doubly-linked list
- Three allocation strategies:
  - First-fit: Returns first block that fits
  - Best-fit: Returns smallest block that fits
  - Next-fit: Continues from last allocation point
- Automatic coalescing of adjacent free blocks
- Block splitting to reduce fragmentation
- Support for both sbrk() and mmap()
- 16-byte memory alignment

## Building

```bash
make          # Build with optimizations
make debug    # Build with debug symbols and sanitizers
make run      # Build and run test program
make test     # Build debug version and run tests
make clean    # Remove build artifacts
```

## API

### Allocation Functions

```c
void *tiny_alloc(size_t size);
void tiny_free(void *ptr);
void *tiny_calloc(size_t nmemb, size_t size);
void *tiny_realloc(void *ptr, size_t size);
```

### Configuration

```c
void tiny_set_strategy(alloc_strategy_t strategy);
void tiny_print_stats(void);
```

Available strategies:
- `FIRST_FIT`
- `BEST_FIT`
- `NEXT_FIT`

## Configuration Options

Edit `main.c` to change:

- `USE_MMAP`: Set to 1 for mmap(), 0 for sbrk()
- `ALIGNMENT`: Memory alignment (default: 16 bytes)
- `MIN_BLOCK_SIZE`: Minimum block size (default: 32 bytes)
- `MMAP_THRESHOLD`: Size threshold for mmap() (default: 128KB)

## Implementation Details

### Block Structure

Each block has a header containing:
- Size (including header)
- Free flag
- Next/previous pointers for free list
- mmap flag

### Memory Layout

```
[header][user data][header][user data]...
```

### Coalescing

Adjacent free blocks are merged when:
- A block is freed
- The freed block is adjacent to existing free blocks
- Blocks were not allocated with mmap()

### Large Allocations

When `USE_MMAP` is enabled, allocations larger than `MMAP_THRESHOLD` use mmap() instead of sbrk(). These blocks:
- Are allocated independently
- Cannot be coalesced with other blocks
- Are unmapped directly on free

## Testing

The included test program demonstrates:
- All three allocation strategies
- Block splitting
- Coalescing behavior
- Memory reuse patterns

## License

Public, have fun.
