/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Generic Linux boot protocol using the EFI/PE entry point of the kernel. Passes
 * initrd with the LINUX_INITRD_MEDIA_GUID DevicePath and cmdline with
 * EFI LoadedImageProtocol.
 *
 * This method works for Linux 5.8 and newer on ARM/Aarch64, x86/x68_64 and RISC-V.
 */

#include "efi-log.h"
#include "initrd.h"
#include "linux.h"
#include "pe.h"
#include "proto/device-path.h"
#include "proto/loaded-image.h"
#include "proto/memory-attribute.h"
#include "util.h"

typedef struct {
        MEMMAP_DEVICE_PATH memmap_path;
        EFI_DEVICE_PATH end_path;
} _packed_ KERNEL_FILE_PATH;

static EFI_STATUS memory_mark_ro_x(EFI_MEMORY_ATTRIBUTE_PROTOCOL *memory_proto, struct iovec *nx_section) {
        EFI_STATUS err;

        assert(memory_proto);
        assert(nx_section);

        /* As per MSFT requirement, memory pages need to be marked W^X, so mark code pages RO+X.
         * Firmwares will start enforcing this at some point in the near-ish future.
         * The kernel needs to mark this as supported explicitly, otherwise it will crash.
         * https://microsoft.github.io/mu/WhatAndWhy/enhancedmemoryprotection/
         * https://www.kraxel.org/blog/2023/12/uefi-nx-linux-boot/ */

        err = memory_proto->SetMemoryAttributes(memory_proto, POINTER_TO_PHYSICAL_ADDRESS(nx_section->iov_base), nx_section->iov_len, EFI_MEMORY_RO);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Cannot make kernel image read-only: %m");

        err = memory_proto->ClearMemoryAttributes(memory_proto, POINTER_TO_PHYSICAL_ADDRESS(nx_section->iov_base), nx_section->iov_len, EFI_MEMORY_XP);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Cannot make kernel image executable: %m");

        return EFI_SUCCESS;
}

static EFI_STATUS memory_mark_rw_nx(EFI_MEMORY_ATTRIBUTE_PROTOCOL *memory_proto, struct iovec *nx_section) {
        EFI_STATUS err;

        assert(memory_proto);
        assert(nx_section);

        err = memory_proto->SetMemoryAttributes(memory_proto, POINTER_TO_PHYSICAL_ADDRESS(nx_section->iov_base), nx_section->iov_len, EFI_MEMORY_XP);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Cannot make kernel image non-executable: %m");

        err = memory_proto->ClearMemoryAttributes(memory_proto, POINTER_TO_PHYSICAL_ADDRESS(nx_section->iov_base), nx_section->iov_len, EFI_MEMORY_RO);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Cannot make kernel image writable: %m");

        return EFI_SUCCESS;
}

typedef struct CleanupNxSections {
        EFI_MEMORY_ATTRIBUTE_PROTOCOL *memory_proto;
        struct iovec *sections;
        size_t n_sections;
} CleanupNxSections;

static void cleanup_nx_sections(CleanupNxSections *c) {
        assert(c);

        /* Restore the code sections that were marked RO+X back to RW+NX before their backing pages are
         * freed: EDK2 requires freed buffers to be writable and non-executable (it may overwrite them with
         * a fixed pattern), otherwise FreePages() crashes. */
        if (c->memory_proto)
                for (size_t i = 0; i < c->n_sections; i++)
                        (void) memory_mark_rw_nx(c->memory_proto, &c->sections[i]);

        free(c->sections);
}

EFI_STATUS linux_exec(
                EFI_HANDLE parent_image,
                const char16_t *cmdline,
                const struct iovec *kernel,
                const struct iovec *initrd) {

        size_t kernel_size_in_memory = 0;
        uint32_t entry_point, section_alignment;
        EFI_STATUS err;

        assert(parent_image);
        assert(iovec_is_set(kernel));
        assert(iovec_is_valid(initrd));

        err = pe_kernel_info(kernel->iov_base, kernel->iov_len, &entry_point, &kernel_size_in_memory, &section_alignment);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Bad kernel image: %m");

        _cleanup_free_ KERNEL_FILE_PATH *kernel_file_path = xnew(KERNEL_FILE_PATH, 1);
        *kernel_file_path = (KERNEL_FILE_PATH) {
                .memmap_path = {
                        .Header = {
                                .Type = HARDWARE_DEVICE_PATH,
                                .SubType = HW_MEMMAP_DP,
                                .Length = sizeof(MEMMAP_DEVICE_PATH),
                        },
                        .MemoryType = EfiLoaderData,
                        .StartingAddress = POINTER_TO_PHYSICAL_ADDRESS(kernel->iov_base),
                        /* NB: the UEFI spec doesn't clarify whether the EndingAddress field should point to
                         * the very last byte or the byte one after. EDK2 puts the very last byte in this
                         * field, hence let's do so here too. Note that iovec_is_set() check above ensured
                         * this cannot underflow. */
                        .EndingAddress = POINTER_TO_PHYSICAL_ADDRESS(kernel->iov_base) + kernel->iov_len - 1,
                },
                .end_path = {
                        .Type = END_DEVICE_PATH_TYPE,
                        .SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE,
                        .Length = sizeof(EFI_DEVICE_PATH),
                },
        };

        EFI_LOADED_IMAGE_PROTOCOL *parent_loaded_image;
        err = BS->HandleProtocol(
                        parent_image, MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL), (void **) &parent_loaded_image);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Cannot get parent loaded image: %m");

        err = pe_kernel_check_no_relocation(kernel->iov_base);
        if (err != EFI_SUCCESS)
                return err;

        /* As per MSFT requirement, memory pages need to be marked W^X, so mark code pages RO+X.
         * Firmwares will start enforcing this at some point in the near-ish future.
         * The kernel needs to mark this as supported explicitly, otherwise it will crash.
         * https://microsoft.github.io/mu/WhatAndWhy/enhancedmemoryprotection/
         * https://www.kraxel.org/blog/2023/12/uefi-nx-linux-boot/ */
        EFI_MEMORY_ATTRIBUTE_PROTOCOL *memory_proto = NULL;

        if (pe_kernel_check_nx_compat(kernel->iov_base)) {
                /* LocateProtocol() is not quite that quick if you have many protocols, so only look for it
                 * if required for NX_COMPAT */
                err = BS->LocateProtocol(MAKE_GUID_PTR(EFI_MEMORY_ATTRIBUTE_PROTOCOL), /* Registration= */ NULL, (void **) &memory_proto);
                if (err != EFI_SUCCESS)
                        log_debug_status(err, "No EFI_MEMORY_ATTRIBUTE_PROTOCOL found, skipping NX_COMPAT support.");
        }

        const PeSectionHeader *headers;
        size_t n_headers;

        err = pe_section_table_from_base(kernel->iov_base, kernel->iov_len, &headers, &n_headers, /* ret_size_in_memory= */ NULL);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Cannot read sections: %m");

        /* Honor the PE SectionAlignment (SZ_64K on arm64): if _text is not aligned the kernel's EFI stub
         * reallocates and copies the image, which can fail with EFI_OUT_OF_RESOURCES on memory-constrained
         * firmware. When alignment <= EFI_PAGE_SIZE (e.g. x86_64) xmalloc_aligned_pages() reduces to a
         * plain AllocatePages() with no extra over-allocation. pe_kernel_info() already sanitized a
         * non-conforming SectionAlignment to plain page alignment. */
        _cleanup_pages_ Pages loaded_kernel_pages = xmalloc_aligned_pages(
                        AllocateAnyPages,
                        EfiLoaderCode,
                        EFI_SIZE_TO_PAGES(kernel_size_in_memory),
                        section_alignment,
                        /* addr= */ 0);

        uint8_t* loaded_kernel = PHYSICAL_ADDRESS_TO_POINTER(loaded_kernel_pages.addr);

        /* Any code section marked RO+X must be reverted to RW+NX before the backing pages are freed. */
        _cleanup_(cleanup_nx_sections) CleanupNxSections nx_restore = {
                .memory_proto = memory_proto,
        };

        FOREACH_ARRAY(h, headers, n_headers) {
                if (h->PointerToRelocations != 0)
                        return log_error_status(EFI_LOAD_ERROR, "Inner kernel image contains sections with relocations, which we do not support.");
                if (h->SizeOfRawData == 0)
                        continue;

                if (UINT32_MAX - h->VirtualAddress < h->SizeOfRawData)
                        return log_error_status(EFI_LOAD_ERROR, "Invalid PE section, SizeOfRawData + VirtualAddress, overflows");
                if (h->VirtualAddress + h->SizeOfRawData > kernel_size_in_memory)
                        return log_error_status(EFI_LOAD_ERROR, "Section would write outside of memory");
                if (h->SizeOfRawData > h->VirtualSize)
                        return log_error_status(EFI_LOAD_ERROR, "Invalid PE section, raw data size is greater than virtual size");
                if (UINT32_MAX - h->VirtualAddress < h->VirtualSize)
                        return log_error_status(EFI_LOAD_ERROR, "Invalid PE section, VirtualSize + VirtualAddress overflows");
                if (h->VirtualAddress + h->VirtualSize > kernel_size_in_memory)
                        return log_error_status(EFI_LOAD_ERROR, "Section virtual size would write outside of memory");
                if (UINT32_MAX - h->PointerToRawData < h->SizeOfRawData)
                        return log_error_status(EFI_LOAD_ERROR, "Invalid PE section, PointerToRawData + SizeOfRawData overflows");
                if (h->PointerToRawData + h->SizeOfRawData > kernel->iov_len)
                        return log_error_status(EFI_LOAD_ERROR, "Invalid PE section, raw data extends outside of file");
                memcpy(loaded_kernel + h->VirtualAddress,
                       (const uint8_t*)kernel->iov_base + h->PointerToRawData,
                       h->SizeOfRawData);
                memzero(loaded_kernel + h->VirtualAddress + h->SizeOfRawData,
                        h->VirtualSize - h->SizeOfRawData);

                /* Not a code section? Nothing to do, leave as-is. */
                if (memory_proto && (h->Characteristics & (PE_CODE|PE_EXECUTE))) {
                        /* Record the section for cleanup before marking it RO+X: if memory_mark_ro_x()
                         * fails after partially applying the attributes, cleanup still reverts them. */
                        nx_restore.sections = xrealloc(nx_restore.sections, nx_restore.n_sections * sizeof(struct iovec), (nx_restore.n_sections + 1) * sizeof(struct iovec));
                        nx_restore.sections[nx_restore.n_sections++] = IOVEC_MAKE(loaded_kernel + h->VirtualAddress, h->VirtualSize);

                        err = memory_mark_ro_x(memory_proto, &nx_restore.sections[nx_restore.n_sections - 1]);
                        if (err != EFI_SUCCESS)
                                return err;
                }
        }

        /* Patch the parent_image(_handle) and parent_loaded_image for the kernel image we are about to execute.
         * We have to do this, because if kernel stub code passes its own handle to certain firmware functions,
         * the firmware could cast EFI_LOADED_IMAGE_PROTOCOL * to a larger struct to access its own private data,
         * and if we allocated a smaller struct, that could cause problems.
         * This is modeled exactly after GRUB behaviour, which has proven to be functional. */
        EFI_LOADED_IMAGE_PROTOCOL original_parent_loaded_image = *parent_loaded_image;
        parent_loaded_image->FilePath = &kernel_file_path->memmap_path.Header;
        parent_loaded_image->ImageBase = loaded_kernel;
        parent_loaded_image->ImageSize = kernel_size_in_memory;

        if (cmdline) {
                parent_loaded_image->LoadOptions = (void *) cmdline;
                parent_loaded_image->LoadOptionsSize = strsize16(parent_loaded_image->LoadOptions);
        }

        _cleanup_(cleanup_initrd) EFI_HANDLE initrd_handle = NULL;
        err = initrd_register(initrd, &initrd_handle);
        if (err != EFI_SUCCESS) {
                /* Restore the patched fields before kernel_file_path and loaded_kernel_pages are freed,
                 * otherwise the stub's own EFI_LOADED_IMAGE_PROTOCOL is left pointing at freed memory. */
                *parent_loaded_image = original_parent_loaded_image;
                return log_error_status(err, "Error registering initrd: %m");
        }

        log_wait();

        EFI_IMAGE_ENTRY_POINT entry =
                (EFI_IMAGE_ENTRY_POINT) ((const uint8_t *) parent_loaded_image->ImageBase + entry_point);
        err = entry(parent_image, ST);

        /* Restore */
        *parent_loaded_image = original_parent_loaded_image;

        return log_error_status(err, "Error starting kernel image: %m");
}
