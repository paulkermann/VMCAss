#include <efi.h>
#include <efilib.h>
#include <efiprot.h>
#include "platform.h"

#define __FORCE_ORDER "m"(*(unsigned int *)0x1000UL)

void* virtual_to_physical(void* virtual_address){
  return virtual_address;
}

void* physical_to_virtual(void* physical_address){
  return physical_address;
}

void* allocate_alligned_physical_page() {
  EFI_PHYSICAL_ADDRESS address = 0;
  EFI_STATUS result = uefi_call_wrapper(gBS->AllocatePages, 4, AllocateAnyPages, EfiReservedMemoryType, 1, &address);
  if (result != EFI_SUCCESS){
    printk(L"[x] Allocate pages failed with result: %d\n", result);
    return 0;
  }
  printk(L"[i] Allocated address %llx\n", address);
  return (void*)address;
}

void free_physical_page(void* physical_address){
  EFI_STATUS result = uefi_call_wrapper(gBS->FreePages, 2, physical_address, 1);
  if (result != EFI_SUCCESS){
    printk(L"[x] failed FreePages: %d\n", result);
  }
}

uint64_t do_rdmsr(uint32_t msr)
{
    uint64_t msr_value;
    asm volatile("rdmsr" : "=A"(msr_value) : "c"(msr));
    return msr_value;
}

uint64_t read_cr4(){
  uint64_t val = 0;
  asm volatile("mov %%cr4,%0\n\t" : "=r" (val) : __FORCE_ORDER);

  return val;
}

void write_cr4(uint64_t val){
  asm volatile("mov %0,%%cr4": "+r" (val) : : "memory");
}

uint64_t read_cr0(){
  uint64_t val = 0;
  asm volatile("mov %%cr0,%0\n\t" : "=r" (val) : __FORCE_ORDER);

  return val;
}

void write_cr0(uint64_t val){
  asm volatile("mov %0,%%cr0": "+r" (val) : : "memory");
}
