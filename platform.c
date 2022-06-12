#include <efi.h>
#include <efilib.h>
#include <efiprot.h>
#include "platform.h"

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
    printk(L"Allocate pages failed with result: %d", result);
    return 0;
  }

  return (void*)address;
}

void free_physical_page(void* physical_address){
  EFI_STATUS result = uefi_call_wrapper(gBS->FreePages, 2, physical_address, 1);
  if (result != EFI_SUCCESS){
    printk(L"failed FreePages: %d", result);
  }
}

uint64_t do_rdmsr(uint32_t msr)
{
    uint64_t msr_value;
    asm volatile("rdmsr" : "=A"(msr_value) : "c"(msr));
    return msr_value;
}