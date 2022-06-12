# Uefi VMCS structure extractor.
Based on the rekall kernel module.
Should run via the UEFI shell.

#### Build
`make all`
Will compile the EFI executable (named quartz.efi) and place it in the root directory.
The compiled binary is 64bit.

#### Test
`make run` will copy the efi executable to the `hd` directory and run it via QEMU(only x86-64 tested)