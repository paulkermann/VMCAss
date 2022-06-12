#ifndef PLATFORM_H
#define PLATFORM_H

#include <stdint.h>
#include <stdbool.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;

#define printk(format, ...) Print(format, ## __VA_ARGS__)


void* virtual_to_physical(void* virtual_address);

void* physical_to_virtual(void* physical_address);

void* allocate_alligned_physical_page();

void free_physical_page(void* physical_address);

uint64_t do_rdmsr(uint32_t msr);

uint64_t read_cr4();

void write_cr4(uint64_t value);

uint64_t read_cr0();

void write_cr0(uint64_t value);

#define ENOMEM 5

#endif