#include <efi.h>
#include <efilib.h>
#include <efiprot.h>
#include "vmcs_logic.h"

EFI_STATUS EFIAPI efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
  InitializeLib(ImageHandle, SystemTable);
  vmxon_init();

  return EFI_SUCCESS;
}
