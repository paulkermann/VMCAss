#include <string.h>
#include <cpuid.h>
#include "vmcs_layout.h"
#include "platform.h"


#define MYPAGE_SIZE 4096
#define IA32_VMX_BASIC_MSR 0x480
#define IA32_FEATURE_CONTROL_MSR 0x3A
#define IA32_VMX_PROCBASED_CTLS_MSR 0x482
#define IA32_VMX_PROCBASED_CTLS2_MSR 0x48B
#define IA32_VMX_TRUE_PROCBASED_CTLS_MSR 0x48E

#define IA32_VMX_CR0_FIXED0 0x486
#define IA32_VMX_CR0_FIXED1 0x487
#define IA32_VMX_CR4_FIXED0 0x488
#define IA32_VMX_CR4_FIXED1 0x489

#define CPUID_VMX_BIT 5
#define NOTFOUND 0xFFFFFFFF

// Needles used to discover the VMCS
#define CONSTANT16  0x1337
#define CONSTANT32  0x13371337ul
#define CONSTANT64  0x1337133713371337ull

bool alloc_failure = false;
int vmx_rev_id = 0;
int vmxon_success = 0;
int vmxoff_success = 0;
int vmptrld_success = 0;
int vmclear_success = 0;
int vmwrite_success = 0;
int vmread_success = 0;
int vmlaunch_success = 0;
char *vmxon_region = NULL;
char *vmcs_guest_region = NULL;

void* vmxon_phy_region = 0;
void* vmcs_phy_region = 0;
void* vmcs_alt_phy_region = 0;

long int rflags_value = 0;

inline static void store_rflags(void);
static void print_vmerror(void);
static void vmclear(void**);
static void vmptrld(void**);
static void vmxon_exit(void);
static u64 vmread(unsigned long field);

#define MAX_REGIONS 64
// Stores virtual addresses of memory regions.
void* regions[MAX_REGIONS];
// Stores physical addresses of memory regions.
void* phy_regions[MAX_REGIONS];

#define MY_VMX_VMXON_RAX        ".byte 0xf3, 0x0f, 0xc7, 0x30"
#define MY_VMX_VMPTRLD_RAX      ".byte 0x0f, 0xc7, 0x30"
#define MY_VMX_VMCLEAR_RAX      ".byte 0x66, 0x0f, 0xc7, 0x30"
#define MY_VMX_VMLAUNCH         ".byte 0x0f, 0x01, 0xc2"
#define MY_VMX_VMRESUME         ".byte 0x0f, 0x01, 0xc3"
#define MY_VMX_VMREAD_RDX_RAX   ".byte 0x0f, 0x78, 0xd0"
#define MY_VMX_VMWRITE_RAX_RDX  ".byte 0x0f, 0x79, 0xd0"
#define MY_VMX_VMXOFF           ".byte 0x0f, 0x01, 0xc4"
#define MY_VMX_VMCALL           ".byte 0x0f, 0x01, 0xc1"
#define MY_HLT                  ".byte 0xf4"

uint64_t adjust_cr0_value(uint64_t old_cr0_value){
    uint64_t fixed0_cr0_flags = do_rdmsr(IA32_VMX_CR0_FIXED0);
    uint64_t fixed1_cr0_flags = do_rdmsr(IA32_VMX_CR0_FIXED1);
    uint64_t new_cr0_value = old_cr0_value;
    new_cr0_value &= fixed1_cr0_flags;
    new_cr0_value |= fixed0_cr0_flags;

    return new_cr0_value;
}

uint64_t adjust_cr4_value(uint64_t old_cr4_value){
    uint64_t fixed0_cr4_flags = do_rdmsr(IA32_VMX_CR4_FIXED0);
    uint64_t fixed1_cr4_flags = do_rdmsr(IA32_VMX_CR4_FIXED1);
    uint64_t new_cr4_value = old_cr4_value;
    new_cr4_value &= fixed1_cr4_flags;
    new_cr4_value |= fixed0_cr4_flags;

    return new_cr4_value;
}

static void display_brand(){
	uint32_t brand[12];

    if (!__get_cpuid_max(0x80000004, NULL)) {
        printk(L"Feature not implemented.");
    }

    __get_cpuid(0x80000002, brand+0x0, brand+0x1, brand+0x2, brand+0x3);
    __get_cpuid(0x80000003, brand+0x4, brand+0x5, brand+0x6, brand+0x7);
    __get_cpuid(0x80000004, brand+0x8, brand+0x9, brand+0xa, brand+0xb);

    printk(L"[i] Brand: %a\n", brand);
}

// Reads a VMCS field by its encoding.
static u64 vmread(unsigned long field) {
    u64 value = 0;
    vmread_success = 0;
    asm volatile("vmread %1, %0\n"
                 : "=a"(value) : "d"(field) : "cc");
    asm volatile("jbe vmread_fail\n");
    vmread_success = 1;
    asm volatile("jmp vmread_finish\n");
    asm volatile("vmread_fail:\n");
    store_rflags();
    printk(L"   # vmread(0x%lX) failed\n", field);
    printk(L"   # RFLAGS: 0x%lX\n", rflags_value);
    //printk(L"   # INSTR_ERROR: 0x%llX\n", vmread(VMX_INSTR_ERROR));
    vmread_success = 0;
    asm volatile("vmread_finish:\n");
    return value;
}

// Writes to a VMCS field by its encoding.
static void vmwrite(unsigned long field, unsigned long value) {
    asm volatile(MY_VMX_VMWRITE_RAX_RDX
                 : : "a"(value), "d"(field) : "cc");
    asm volatile("jbe vmwrite_fail\n");
    vmwrite_success = 1;
    asm volatile("jmp vmwrite_finish\n"
                 "vmwrite_fail:\n");
    store_rflags();
    vmwrite_success = 0;
    printk(L"   # vmwrite(0x%0lX, 0x%0lX) failed\n", field, value);
    print_vmerror();
    asm volatile("vmwrite_finish:\n");
}

/* Finds a 2-byte value in the physical page pointed by vmcs_phys_page and
 * returns the offset. If not found, returns NOTFOUND */
static unsigned int find_16(void *vmcs_phys_page, u16 value)
{
    unsigned int i = 0;
    for (; i < MYPAGE_SIZE - 2; i++)
    {
        if ((*(u16*)(vmcs_phys_page + i)) == value)
        {
            return i;
        }
    }
    return NOTFOUND;
}

/* Finds a 4-byte value in the physical page pointed by vmcs_phys_page and
 * returns the offset. If not found, returns NOTFOUND */
static int find_32(void *vmcs_phys_page, u32 value)
{
    unsigned int i = 0;
    for (; i < MYPAGE_SIZE - 4; i++)
    {
        if ((*(u32*)(vmcs_phys_page + i)) == value)
        {
            return i;
        }
    }
    return NOTFOUND;
}

/* Finds a 8-byte value in the physical page pointed by vmcs_phys_page and
 * returns the offset. If not found, returns NOTFOUND */
static int find_64(void *vmcs_phys_page, u64 value)
{
    unsigned int i = 0;
    for (; i < MYPAGE_SIZE - 8; i++)
    {
        if ((*(u64*)(vmcs_phys_page + i)) == value)
        {
            return i;
        }
    }
    return NOTFOUND;
}

/* Dumps out a memory region. */
static void print_region(char *region)
{
    int i;
    printk(L"[i] memory dump of region %lx:\n[i] ", region);
    for (i=0; i<MYPAGE_SIZE; i++)
    {
        if (!(i % 4)) printk(L" ");
        if (! (i % 8)) printk(L" ");
        if (! (i % 32)) printk(L"\n[i] ");
        printk(L"%02x", *(unsigned char*)(region+i));
    }
    printk(L"\n");
}

/* Discovers the layout of the VMCS used by the processor in which
 * this module is being run. No attempts at discovery of other processors
 * is done on multi-processor systems.
 */
static void discover_vmcs(void)
{
    int i = 0;
    unsigned int index = 0;
    unsigned int result = 0;
    FIELD_INFO current_field;
    u64 field_value = 0;
    unsigned short saved_16 = 0;
    unsigned int saved_32 = 0;
    u64 saved_64 = 0;
    unsigned long encoding_width = 0;
    unsigned int field_index = 0;
    // By default, a field is not validated
    unsigned int validated = 0;
    unsigned int readonly = 0;
    int region_idx = 0;
    unsigned int found = 0;
    unsigned int needs_force_flush = 0;
    unsigned int is_high = 0;
    char* field_datatype = NULL;


    printk(L"[i] Force-flush testing...\n");
    /* 1) Force-flush testing.
     * Usually, the VMCS is maintained in memory, so after doing a vmptrld of a
     * memory region, any subsequent vmwrites will write to memory.
     *
     * Some processors (i.e: Xeon Westmere, Haswells) have in-chip storage of
     * the VMCS. Because we rely on being able to manipulate fields and see the
     * effect this has in memory, we need to first determine if we need to force
     * the processor to load the VMCS off memory.
     *
     * To check for it, we set up a control VMCS, load it and write a VMCS value
     * that's available in all VME revisions. Then, we try to find it in memory
     * in the same VMCS region that we marked as current.
     *
     * If we cannot find it, it means the processor is using alternate means to
     * store the VMCS.
     *
     * We then ask the processor to load as many memory regions as needed in
     * order to overflow its storage capacity and force it to dump our control
     * VMCS to memory. Once we find the needle in memory, we know the next
     * VMPTRLD will force the processor to load our control VMCS.
     */
    saved_64 = vmread(GUEST_CR3);
    printk(L"[i] Saved GUEST_CR3 = %llx\n", saved_64);
    vmwrite(GUEST_CR3, CONSTANT64);

    if (find_64(vmcs_guest_region, CONSTANT64) == NOTFOUND) {
        // Needle not found, so we'll probably need to force-flush.
        needs_force_flush = 1;
        printk(L"[i] Needle not found. Force-flush technique required.\n");

        // Initialize the force-flush regions.
        for (i = 0; i < MAX_REGIONS; i++)
        {
             phy_regions[i] = 0;
             regions[i] = NULL;
        }

        // We'll try to find how many additional VMCS we need to allocate to
        // force a flush.
        // We start allocating and switching the current_active VMCS and trying
        // to find it in the original VMCS, to see when/if it gets flushed to
        // memory.
        for(region_idx = 0; !found && (region_idx < MAX_REGIONS); region_idx++)
        {
            regions[region_idx] = physical_to_virtual(allocate_alligned_physical_page());
            // We need to fill the revision ID to make it a valid VMCS region.
            memcpy(regions[region_idx], &vmx_rev_id, 4);
            phy_regions[region_idx] = virtual_to_physical(regions[region_idx]);

            printk(L"[i] Loading region %lx (%016lX)\n",
                   regions[region_idx], phy_regions[region_idx]);
            vmcs_alt_phy_region = phy_regions[region_idx];
            vmptrld(&phy_regions[region_idx]);
            result = find_64(vmcs_guest_region, CONSTANT64);
            if (result != NOTFOUND)
            {
                found = 1;
                break;
            }
        }
        if (!found){
            printk(L"[x] NOT FOUND after %d regions.\n", region_idx + 1);
        } else {
            printk(L"[i] FOUND AFTER %d regions, at offset %d\n",
                   region_idx + 1, result);
            print_region(vmcs_guest_region);
        }
        printk(L"[i] vmclearing and freeing %d regions\n", region_idx+1);
        for (i = 0; i < MAX_REGIONS && regions[i] != NULL; i++) {
            vmcs_alt_phy_region = phy_regions[i];
            vmclear(&phy_regions[i]);
            free_physical_page(physical_to_virtual(regions[i]));
        }
    } else {
        printk(L"[!] Needle found in memory. Force-flush is NOT required.\n");
    }
    
    if (!found){
        printk(L"[x] Could not find field. Aborting!\n");
        return;
    }

    /* 2) Actual discovery code
     * At this point if we had to force-flush regions we just overflowed the
     * processor's storage. The next VMPTRLD will force the processor to load
     * the region from memory, thus allowing us to. It could happen that the
     * processor could automatically load memory regions from disk as we VMCLEAR
     * them. However, I've never seen this happen (yet).
     *
     * Now, we fill the vmcs_guest region with 16 bit values which are the
     * indexes into the vmcs to help us locate fields (even read-only ones).
     * */
    for (index=4; index < MYPAGE_SIZE; index += 2)
    {
        *(unsigned short*)(vmcs_guest_region + index) = index;
    }
    memcpy(vmcs_guest_region, &vmx_rev_id, 4);

    if (needs_force_flush)
    {
        // With the region filled in, we force the processor to load it.
        // Because this was not the current active VMCS region, and we forced a
        // flush to memory earlier, this region now HAS to be loaded by the
        // processor from memory, leaking the positions of all the available
        // fields.
        vmptrld(&vmcs_phy_region);
        printk(L"[i] Will NOT write-validate fields.\n");
    }
    printk(L"NEW_VMCS_0x%X\n", vmx_rev_id);

    for (i = 0, current_field = field_table[i];
         current_field.field_name != NULL;
         current_field = field_table[++i])
    {
        field_value = vmread(current_field.encoding);

        if (vmread_success == 0)
        {
            printk(L"[x]   # %a\tINVALID_FIELD\n", current_field.field_name);
            continue;
        }

        // First validation step
        field_index = field_value & 0xFFFFull;
        if (field_index < 0x8)
        {
            // A field cannot exist at offset below 8 because 0 is the
            // REVISION_ID and 4 is the ABORT_INDICATOR.
            // Contrary to what the manuals say, vmread always seems to succeed
            // (at least for known encodings), even for fields that are not
            // present on a microarchitecture, so you usually get a value of 0
            // for fields that are not valid.
            // TODO: Consider confirming these cases with a vmwrite that fails.
            printk(L"[x]   # %s reported being at offset %d which is impossible\n",
                   current_field.field_name, field_index);
            continue;
        }
        // Some fields are not aligned to 2... here we try to fix the reported
        // value.
        // This is mostly just the segment selectors for now.
        // According to the manuals, the VMCS only fills the first 1K of the
        // page, so we set w, we assu
        if ( field_index > 0x1000)
        {
            // !!WARNING!! HACK HACK HACK for values not aligned to 2.
            printk(L"[x]   # %a\t%d\tMISALIGNED\n",
                   current_field.field_name, field_index);
            field_index = (((field_index & 0xFF00) >> 8)
                           | ((field_index & 0x00FF) << 8)) - 1;
            printk(L"[i]   # %a\t%d\tFIXED\n",
                   current_field.field_name, field_index);
        }

        if (field_index > 0x1000)
        {
            // This is outside the range of the VMCS guest region. Cannot be
            // valid or it was written to between our initialization and the
            // discovery code :(
            printk(L"[x]   # %a\t%d\tOFFBOUNDS\n", current_field.field_name,
                   field_index);
            continue;
        }

        // Reset the validation flag
        validated = 0;
        // Reset the HIGH field flag
        is_high = 0;
        // The width is encoded in bits 14:13
        encoding_width = (current_field.encoding & ((1<<14) | (1<<13))) >> 13;
        // Field is read-only if bits 11:10 == 1
        readonly = ((current_field.encoding & ((1<<11) | (1<<10))) >> 10) == 1;
        // Field holds only the HIGH bytes if it's 64-bits wide and bit 1 is set
        is_high = encoding_width == 1 && current_field.encoding & 1;

        // Second validation, for writable fields only. We attempt to write to
        // it and confirm the offset where we find it.

        if (encoding_width == 0){
        	field_datatype = "unsigned short";
        } else if (encoding_width == 2){
        	field_datatype = "unsigned int";
        } else if (encoding_width == 1){
        	if (current_field.encoding & 1){
        		field_datatype = "unsigned int";
        	} else {
        		field_datatype = "unsigned long long";
        	}
        } else if (encoding_width == 3){
        	field_datatype = "unsigned long long";
        } else {
        	field_datatype = "UNKNOWN";
        }

        if (!readonly && !needs_force_flush)
        { // No validation possible with readonly fields :(
            if (encoding_width == 0)
            { // 16-bit fields
                saved_16 = field_value;
                vmwrite(current_field.encoding, CONSTANT16);
                result = find_16(vmcs_guest_region, CONSTANT16);
                vmwrite(current_field.encoding, field_value);
                field_datatype = "unsigned short";
            } else
            if (encoding_width == 2)
            { // 32-bit fields
                saved_32 = field_value;
                vmwrite(current_field.encoding, CONSTANT32);
                result = find_32(vmcs_guest_region, CONSTANT32);
                vmwrite(current_field.encoding, field_value);
                field_datatype = "unsigned int";
            } else
            if (encoding_width == 1)
            { // 64-bit fields
                vmwrite(current_field.encoding, CONSTANT64);
                if (current_field.encoding & 1)
                {   // This is a high field. High fields return 64:32 in 31:0.
                    // We need to look for a 32-bit value instead.
                    result = find_32(vmcs_guest_region, CONSTANT32);
                    field_datatype = "unsigned int";
                } else
                {
                    result = find_64(vmcs_guest_region, CONSTANT64);
                    field_datatype = "unsigned long long";
                }
                vmwrite(current_field.encoding, field_value);
            } else
            if (encoding_width == 3)
            { // Natural-width fields, which are 64 bits in a 64bit OS.
                vmwrite(current_field.encoding, CONSTANT64);
                result = find_64(vmcs_guest_region, CONSTANT64);
                vmwrite(current_field.encoding, field_value);
                field_datatype = "unsigned long";
            }

            if (result == field_index)
                validated = 1;
            else
                printk(L"[i]   # reported_index = %X | found_index = %X\n",
                       field_index, result);
        }

        printk(L"[v]%a;%d;%a\n", current_field.field_name, field_index, field_datatype);
    }
}


/* Allocate a 4K region for vmxon */
static void allocate_vmxon_region(void)
{
    vmxon_region = physical_to_virtual(allocate_alligned_physical_page());
}

/* Allocate a 4K vmcs region for the guest */
static void allocate_vmcs_region(void)
{
    vmcs_guest_region = physical_to_virtual(allocate_alligned_physical_page());
    memset(vmcs_guest_region, 0, MYPAGE_SIZE);
}

static void deallocate_vmxon_region(void)
{
    if (vmxon_region)
    {
        printk(L"[i] freeing allocated vmxon region!\n");
        free_physical_page(physical_to_virtual(vmxon_region));
    }
}

static void deallocate_vmcs_region(void)
{
    if (vmcs_guest_region)
    {
        printk(L"[i] freeing allocated vmcs region!\n");
        free_physical_page(physical_to_virtual(vmcs_guest_region));
    }
}

static void turn_on_vmxe(void)
{
    printk(L"[i] Turning on cr4.vmxe. Old cr4 value: 0x%llx\n", read_cr4());
    uint64_t cr4 = read_cr4();
    cr4 |= 0x2000;
    write_cr4(cr4);
    printk(L"[i] Turned on cr4.vmxe. New cr4 value: 0x%llx\n", read_cr4());
}

static void turn_off_vmxe(void)
{
    uint64_t cr4 = read_cr4();
    cr4 &= ~0x2000;
    write_cr4(cr4);
    printk(L"[i] Turned off cr4.vmxe\n");
}

inline void store_rflags(void)
{
    asm volatile("pushfq\n");
    asm volatile("popq %0\n"
                 :
                 :"m"(rflags_value)
                 :"memory");
}

static void print_vmerror(void)
{
    printk(L"[x]   # Error code: %llX\n", vmread(INSTR_ERROR));
    printk(L"[x]   # RFLAGS: 0x%lX\n", rflags_value);
}

/*do vmptrld*/
static void vmptrld(void** region) {
    printk(L"[i] Attempting vmptrld(0x%lX) ... ", *region);
    asm volatile(MY_VMX_VMPTRLD_RAX
                 :
		 : "a"(region), "m"(*region)
                 : "cc", "memory");
    asm volatile("jbe vmptrld_fail\n");
    vmptrld_success = 1;
    printk(L"ok!\n");
    asm volatile("jmp vmptrld_finish\n"
                 "vmptrld_fail:\n");
    store_rflags();
    vmptrld_success = 0;
    printk(L"fail!\n");
    print_vmerror();
    asm volatile("vmptrld_finish:\n");
}

static void vmclear(void**region)
{
    asm volatile(MY_VMX_VMCLEAR_RAX
                 :
                 : "a"(region), "m"(*region)
                 : "cc", "memory");
    asm volatile("jbe vmclear_fail");
    vmclear_success = 1;
    asm volatile("jmp vmclear_finish\n"
                 "vmclear_fail:\n");
    store_rflags();
    vmclear_success = 0;
    printk(L"[x] vmclear has failed!\n");
    print_vmerror();
    asm volatile("vmclear_finish:\n");
    printk(L"[i] vmclear done!\n");
}

static void vmxon(void)
{
    asm volatile(MY_VMX_VMXON_RAX
                 :
                 : "a"(&vmxon_phy_region), "m"(vmxon_phy_region)
                 : "memory", "cc");
    asm volatile("jbe vmxon_fail\n");
    vmxon_success = 1;
    asm volatile("jmp vmxon_finish\n"
                 "vmxon_fail:\n");
    store_rflags();
    vmxon_success = 0;
    printk(L"[x] vmxon has failed!\n");
    print_vmerror();
    asm volatile("vmxon_finish:\n");
}

/*do vmxoff*/
static void vmxoff(void)
{
    asm volatile("vmxoff\n" : : : "cc");
    asm volatile("jbe vmxoff_fail\n");
    vmxoff_success = 1;
    asm volatile("jmp vmxoff_finish\n");
    asm volatile("vmxoff_fail:\n");
    store_rflags();
    vmxoff_success = 0;
    printk(L"[x] vmxoff has failed!\n");
    print_vmerror();
    asm volatile("vmxoff_finish:\n");
    printk(L"[i] vmxoff complete\n");
}


static void vmxon_exit(void)
{
    if (vmxon_success == 1)
    {
        printk(L"[i] Machine in vmxon: Attempting vmxoff\n");
        vmclear(&vmcs_phy_region);
        vmxoff();
        vmxon_success = 0;
    }
    turn_off_vmxe();
    deallocate_vmcs_region();
    deallocate_vmxon_region();
}

static int vmxon_init(void)
{
    int cpuid_leaf = 1;
    int cpuid_ecx = 0;
    uint64_t msr3a_value = 0;
    display_brand();

    printk(L"[i] In vmxon_init function\n");

    asm volatile("cpuid\n\t"
                 : "=c"(cpuid_ecx)
                 : "a"(cpuid_leaf)
                 : "%rbx", "%rdx");

    if ((cpuid_ecx >> CPUID_VMX_BIT) & 1)
    {
        printk(L"[i] VMX supported CPU.\n");
    } else
    {
        printk(L"[x] VMX not supported by CPU. Not doing anything\n");
        goto finish_here;
    }

    msr3a_value = do_rdmsr(IA32_FEATURE_CONTROL_MSR);
    printk(L"[i] IA32_FEATURE_CONTROL_MSR = %llX\n", msr3a_value);
    printk(L"[i] IA32_VMX_BASIC_MSR = %llX\n", do_rdmsr(IA32_VMX_BASIC_MSR));
    if (do_rdmsr(IA32_VMX_BASIC_MSR) & (1ull<<55))
    {
        printk(L"[i] TRUE VMX controls supported\n");
        printk(L"[i] IA32_VMX_PROCBASED_CTLS = %llX\n",
              do_rdmsr(IA32_VMX_PROCBASED_CTLS_MSR));
        printk(L"[i] IA32_VMX_PROCBASED_CTLS2 = %llX\n",
              do_rdmsr(IA32_VMX_PROCBASED_CTLS2_MSR));
        printk(L"[i] IA32_VMX_TRUE_PROCBASED_CTLS = %llX\n",
               do_rdmsr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR));
    } else
    {
        printk(L"[i] TRUE VMX controls UNSUPPORTED\n");
        printk(L"[i] IA32_VMX_PROCBASED_CTLS = %llX\n",
               do_rdmsr(IA32_VMX_PROCBASED_CTLS_MSR));
        printk(L"[i] IA32_VMX_PROCBASED_CTLS2 = %llX\n",
              do_rdmsr(IA32_VMX_PROCBASED_CTLS2_MSR));
    }

    if (msr3a_value & 1)
    {
        if ((msr3a_value >> 2) & 1)
        {
            printk(L"[i] MSR 0x3A: Lock bit is on. VMXON bit is on. OK\n");
        } else
        {
            printk(L"[x] MSR 0x3A: Lock bit is on. VMXON bit is off. No VME :(\n");
            goto finish_here;
        }
    } else
    {
        printk(L"[x] MSR 0x3A: Lock bit is not on. Not doing anything."
               "You should activate VT-x.\n");
        goto finish_here;
    }

    allocate_vmxon_region();

    if (vmxon_region == NULL)
    {
        printk(L"[x] Error allocating vmxon region\n");
        vmxon_exit();
        vmxon_success = -ENOMEM;
        return vmxon_success;
    }

    vmxon_phy_region = virtual_to_physical(vmxon_region);
    vmx_rev_id = do_rdmsr(IA32_VMX_BASIC_MSR);
    printk(L"[i] Revision ID: 0x%08X\n", vmx_rev_id);
    memcpy(vmxon_region, &vmx_rev_id, 4);  // copy revision id to vmxon region

    turn_on_vmxe();

    printk(L"[i] Before adjusted cr4 value: %llx\n", read_cr4());
    write_cr4(adjust_cr4_value(read_cr4()));
    printk(L"[i] After adjusted cr4 value: %llx\n", read_cr4());

    printk(L"[i] Before adjusted cr0 value: %llx\n", read_cr0());
    write_cr0(adjust_cr0_value(read_cr0()));
    printk(L"[i] After adjusted cr0 value: %llx\n", read_cr0());

    vmxon();
    printk(L"[i] After vmxon function\n");
    if (!vmxon_success)
    {
        deallocate_vmxon_region();
        goto finish_here;
    }
    printk(L"[i] just before allocate_vmcs_region function\n");
    allocate_vmcs_region();

    if (vmcs_guest_region == NULL)
    {
        printk(L"[x] Error allocating vmcs guest regions\n");
        vmxon_exit();
        vmptrld_success = -ENOMEM;
        return vmptrld_success;
    }
    vmcs_phy_region = virtual_to_physical(vmcs_guest_region);
    memcpy(vmcs_guest_region, &vmx_rev_id, 4); //copy revision id to vmcs region
    vmptrld(&vmcs_phy_region);
    printk(L"[i] Finished vmxon\n");
    printk(L"[i] Revision ID: 0x%08X\n", vmx_rev_id);
    printk(L"[i] Discovering fields\n");
    discover_vmcs();
    vmxon_exit();
finish_here:
    return 0;
}
