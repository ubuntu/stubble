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

EFI_STATUS linux_exec(
                EFI_HANDLE parent_image,
                const char16_t *cmdline,
                const struct iovec *kernel,
                const struct iovec *initrd) {

        size_t kernel_size_in_memory = 0;
        uint32_t entry_point;
        EFI_STATUS err;

        assert(parent_image);
        assert(iovec_is_set(kernel));
        assert(iovec_is_valid(initrd));

        err = pe_kernel_info(kernel->iov_base, &entry_point, /* ret_image_base= */ NULL, &kernel_size_in_memory);
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
                        .EndingAddress = POINTER_TO_PHYSICAL_ADDRESS(kernel->iov_base) + kernel->iov_len,
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
        _cleanup_free_ struct iovec *nx_sections = NULL;
        size_t n_nx_sections = 0;

        if (pe_kernel_check_nx_compat(kernel->iov_base)) {
                /* LocateProtocol() is not quite that quick if you have many protocols, so only look for it
                 * if required for NX_COMPAT */
                err = BS->LocateProtocol(MAKE_GUID_PTR(EFI_MEMORY_ATTRIBUTE_PROTOCOL), /* Registration= */ NULL, (void **) &memory_proto);
                if (err != EFI_SUCCESS)
                        /* Only warn if the UEFI should have support in the first place (version >= 2.10) */
                        log_full(err,
                                 ST->Hdr.Revision >= ((2U << 16) | 100U) ? LOG_WARNING : LOG_DEBUG,
                                 "No EFI_MEMORY_ATTRIBUTE_PROTOCOL found, skipping NX_COMPAT support.");
        }

        const PeSectionHeader *headers;
        size_t n_headers;

        /* Do we need to validate anything here? the len? */
        err = pe_section_table_from_base(kernel->iov_base, &headers, &n_headers);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Cannot read sections: %m");

        /* Do we need to ensure under 4gb address on x86? */
        _cleanup_pages_ Pages loaded_kernel_pages = xmalloc_pages(
                        AllocateAnyPages, EfiLoaderCode, EFI_SIZE_TO_PAGES(kernel_size_in_memory), 0);

        uint8_t* loaded_kernel = PHYSICAL_ADDRESS_TO_POINTER(loaded_kernel_pages.addr);
        FOREACH_ARRAY(h, headers, n_headers) {
                if (h->PointerToRelocations != 0)
                        return log_error_status(EFI_LOAD_ERROR, "Inner kernel image contains sections with relocations, which we do not support.");
                if (h->SizeOfRawData == 0)
                        continue;

                if (h->VirtualAddress + h->SizeOfRawData > kernel_size_in_memory)
                        return log_error_status(EFI_LOAD_ERROR, "Section would write outside of memory");
                memcpy(loaded_kernel + h->VirtualAddress,
                       (const uint8_t*)kernel->iov_base + h->PointerToRawData,
                       h->SizeOfRawData);
                memzero(loaded_kernel + h->VirtualAddress + h->SizeOfRawData,
                        h->VirtualSize - h->SizeOfRawData);

                /* Not a code section? Nothing to do, leave as-is. */
                if (memory_proto && (h->Characteristics & (PE_CODE|PE_EXECUTE))) {
                        nx_sections = xrealloc(nx_sections, n_nx_sections * sizeof(struct iovec), (n_nx_sections + 1) * sizeof(struct iovec));
                        nx_sections[n_nx_sections].iov_base = loaded_kernel + h->VirtualAddress;
                        nx_sections[n_nx_sections].iov_len = h->VirtualSize;

                        err = memory_mark_ro_x(memory_proto, &nx_sections[n_nx_sections]);
                        if (err != EFI_SUCCESS)
                                return err;

                        ++n_nx_sections;
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
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error registering initrd: %m");

        log_wait();

        EFI_IMAGE_ENTRY_POINT entry =
                (EFI_IMAGE_ENTRY_POINT) ((const uint8_t *) parent_loaded_image->ImageBase + entry_point);
        err = entry(parent_image, ST);

        /* Restore */
        *parent_loaded_image = original_parent_loaded_image;

        /* On failure we'll free the buffers. EDK2 requires the memory buffers to be writable and
         * non-executable, as in some configurations it will overwrite them with a fixed pattern, so if the
         * attributes are not restored FreePages() will crash. */
        for (size_t i = 0; i < n_nx_sections; i++)
                (void) memory_mark_rw_nx(memory_proto, &nx_sections[i]);

        return log_error_status(err, "Error starting kernel image: %m");
}
