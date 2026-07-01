/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "chid.h"
#include "devicetree.h"
#include "efi-log.h"
#include "pe.h"
#include "util.h"
#include "proto/dt-fixup.h"

#define DOS_FILE_MAGIC "MZ"
#define PE_FILE_MAGIC  "PE\0\0"

#if defined(__i386__)
#  define TARGET_MACHINE_TYPE 0x014CU
#  define TARGET_MACHINE_TYPE_COMPATIBILITY 0x8664U
#elif defined(__x86_64__)
#  define TARGET_MACHINE_TYPE 0x8664U
#elif defined(__aarch64__)
#  define TARGET_MACHINE_TYPE 0xAA64U
#elif defined(__arm__)
#  define TARGET_MACHINE_TYPE 0x01C2U
#elif defined(__riscv) && __riscv_xlen == 32
#  define TARGET_MACHINE_TYPE 0x5032U
#elif defined(__riscv) && __riscv_xlen == 64
#  define TARGET_MACHINE_TYPE 0x5064U
#elif defined(__loongarch__) && __loongarch_grlen == 32
#  define TARGET_MACHINE_TYPE 0x6232U
#elif defined(__loongarch__) && __loongarch_grlen == 64
#  define TARGET_MACHINE_TYPE 0x6264U
#else
#  error Unknown EFI arch
#endif

#ifndef TARGET_MACHINE_TYPE_COMPATIBILITY
#  define TARGET_MACHINE_TYPE_COMPATIBILITY 0
#endif

bool dtb_override = true;

typedef struct DosFileHeader {
        uint8_t  Magic[2];
        uint16_t LastSize;
        uint16_t nBlocks;
        uint16_t nReloc;
        uint16_t HdrSize;
        uint16_t MinAlloc;
        uint16_t MaxAlloc;
        uint16_t ss;
        uint16_t sp;
        uint16_t Checksum;
        uint16_t ip;
        uint16_t cs;
        uint16_t RelocPos;
        uint16_t nOverlay;
        uint16_t reserved[4];
        uint16_t OEMId;
        uint16_t OEMInfo;
        uint16_t reserved2[10];
        uint32_t ExeHeader;
} _packed_ DosFileHeader;

typedef struct CoffFileHeader {
        uint16_t Machine;
        uint16_t NumberOfSections;
        uint32_t TimeDateStamp;
        uint32_t PointerToSymbolTable;
        uint32_t NumberOfSymbols;
        uint16_t SizeOfOptionalHeader;
        uint16_t Characteristics;
} _packed_ CoffFileHeader;

#define OPTHDR32_MAGIC 0x10B /* PE32  OptionalHeader */
#define OPTHDR64_MAGIC 0x20B /* PE32+ OptionalHeader */

typedef struct PeImageDataDirectory {
        uint32_t VirtualAddress;
        uint32_t Size;
} _packed_ PeImageDataDirectory;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct PeOptionalHeader {
        uint16_t Magic;
        uint8_t  LinkerMajor;
        uint8_t  LinkerMinor;
        uint32_t SizeOfCode;
        uint32_t SizeOfInitializedData;
        uint32_t SizeOfUninitializeData;
        uint32_t AddressOfEntryPoint;
        uint32_t BaseOfCode;
        union {
                struct { /* PE32 */
                        uint32_t BaseOfData;
                        uint32_t ImageBase32;
                };
                uint64_t ImageBase64; /* PE32+ */
        };
        uint32_t SectionAlignment;
        uint32_t FileAlignment;
        uint16_t MajorOperatingSystemVersion;
        uint16_t MinorOperatingSystemVersion;
        uint16_t MajorImageVersion;
        uint16_t MinorImageVersion;
        uint16_t MajorSubsystemVersion;
        uint16_t MinorSubsystemVersion;
        uint32_t Win32VersionValue;
        uint32_t SizeOfImage;
        uint32_t SizeOfHeaders;
        uint32_t CheckSum;
        uint16_t Subsystem;
        uint16_t DllCharacteristics;
        union {
                struct {
                        uint64_t SizeOfStackReserve64;
                        uint64_t SizeOfStackCommit64;
                        uint64_t SizeOfHeapReserve64;
                        uint64_t SizeOfHeapCommit64;
                        uint32_t LoaderFlags64;
                        uint32_t NumberOfRvaAndSizes64;

                        PeImageDataDirectory DataDirectory64[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
                };
                struct {
                        uint32_t SizeOfStackReserve32;
                        uint32_t SizeOfStackCommit32;
                        uint32_t SizeOfHeapReserve32;
                        uint32_t SizeOfHeapCommit32;
                        uint32_t LoaderFlags32;
                        uint32_t NumberOfRvaAndSizes32;

                        PeImageDataDirectory DataDirectory32[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
                };
        };
} _packed_ PeOptionalHeader;

typedef struct PeFileHeader {
        uint8_t  Magic[4];
        CoffFileHeader FileHeader;
        PeOptionalHeader OptionalHeader;
} _packed_ PeFileHeader;

#define SECTION_TABLE_BYTES_MAX (16U * 1024U * 1024U)

static void pe_locate_sections_internal(
                const PeSectionHeader section_table[],
                size_t n_section_table,
                const char *const section_names[],
                size_t validate_base,
                const void *device_table,
                const Device *device,
                PeSectionVector sections[]);

static bool verify_dos(const DosFileHeader *dos) {
        assert(dos);

        DISABLE_WARNING_TYPE_LIMITS;
        return memcmp(dos->Magic, DOS_FILE_MAGIC, STRLEN(DOS_FILE_MAGIC)) == 0 &&
                dos->ExeHeader >= sizeof(DosFileHeader) &&
                (size_t) dos->ExeHeader <= SIZE_MAX - sizeof(PeFileHeader);
        REENABLE_WARNING;
}

static bool verify_pe(
                const DosFileHeader *dos,
                const PeFileHeader *pe,
                bool allow_compatibility) {

        assert(dos);
        assert(pe);

        return memcmp(pe->Magic, PE_FILE_MAGIC, STRLEN(PE_FILE_MAGIC)) == 0 &&
                (pe->FileHeader.Machine == TARGET_MACHINE_TYPE ||
                 (allow_compatibility && pe->FileHeader.Machine == TARGET_MACHINE_TYPE_COMPATIBILITY)) &&
                pe->FileHeader.NumberOfSections > 0 &&
                IN_SET(pe->OptionalHeader.Magic, OPTHDR32_MAGIC, OPTHDR64_MAGIC) &&
                pe->FileHeader.SizeOfOptionalHeader < SIZE_MAX - (dos->ExeHeader + offsetof(PeFileHeader, OptionalHeader));
}

static size_t section_table_offset(const DosFileHeader *dos, const PeFileHeader *pe) {
        assert(dos);
        assert(pe);

        return dos->ExeHeader + offsetof(PeFileHeader, OptionalHeader) + pe->FileHeader.SizeOfOptionalHeader;
}

static bool pe_section_name_equal(const char *a, const char *b) {

        if (a == b)
                return true;
        if (!a != !b)
                return false;

        /* Compares up to 8 characters of a and b i.e. the name size limit in the PE section header */

        for (size_t i = 0; i < sizeof_field(PeSectionHeader, Name); i++) {
                if (a[i] != b[i])
                        return false;

                if (a[i] == 0) /* Name is shorter than 8 */
                        return true;
        }

        return true;
}

static const char* skip_whitespace(const char *p, const char *end) {
        while (p < end && (*p == ' ' || *p == '\t'))
                p++;
        return p;
}

/**
 * get_prop_end() - Determine the length of a machdb property value
 * @p: Pointer to the start of the property value (e.g. right after the "Compatible:" keyword)
 * @end: Pointer to the end of the machdb section (i.e. one past its last byte)
 *
 * The value pointed to by @p ends at whichever comes first: the line feed or NUL byte terminating
 * the current line, or @end (the end of the machdb section). Any whitespace (space or tab), and a
 * trailing carriage return, immediately preceding that point are not considered part of the value.
 *
 * Return: the length of the property value, in bytes, excluding any trailing line feed, NUL byte,
 * carriage return, or whitespace.
 */
static size_t get_prop_end(const char *p, const char *end) {
        assert(p);
        assert(end >= p);

        const char *e = p;

        /* Find the end of the line: either a line feed, a NUL byte, or the end of the section */
        while (e < end && *e != '\n' && *e != '\0')
                e++;


        /* Trim any trailing whitespace (and a trailing carriage return) before that point */
        while (e > p && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r'))
                e--;

        return (size_t) (e - p);
}

/**
 * machdb_lookup_model() - Look up the Compatible: value for a given Model: in a machdb section
 * @machdb: Pointer to the start of the .machdb section
 * @machdb_size: Size of the .machdb section
 * @model: The firmware devicetree's /model property to look up
 * @ret_compatible: On success, set to point at the start of the (not NUL-terminated) compatible
 *                  string within @machdb. Set to NULL if no matching entry is found.
 *
 * The .machdb section has the format:
 *   Model: <model_string>
 *   ...
 *   Compatible: <compatible_string>
 *
 * There can be multiple "Model:" entries before a "Compatible:" entry.
 *
 * Return: the length of the compatible string pointed to by *ret_compatible (excluding any
 * trailing line feed, carriage return, or whitespace), or 0 if no matching entry was found.
 */
static size_t machdb_lookup_model(
                const char *machdb,
                size_t machdb_size,
                const char *model,
                const char **ret_compatible) {

        assert(ret_compatible);

        *ret_compatible = NULL;

        if (!machdb || !model || machdb_size == 0)
                return 0;

        const char *cursor = machdb;
        const char *end = machdb + machdb_size;
        bool model_matched = false;

        while (cursor < end) {
                const char *line_start = cursor;
                const char *line_end = cursor;

                while (line_end < end && *line_end != '\n' && *line_end != '\r' && *line_end != '\0')
                        line_end++;

                const char *p = skip_whitespace(line_start, line_end);

                /* Check if line starts with "Model:" */
                if (line_end - p >= 8 && strncmp8(p, "Model:", 6) == 0) {
                        p = skip_whitespace(p + 6, line_end);

                        /* Compare with the model we're looking for */
                        size_t model_len = strlen8(model);
                        if ((size_t)(line_end - p) >= model_len && strncmp8(p, model, model_len) == 0) {
                                /* Make sure we have an exact match (followed by whitespace or end of line) */
                                if (p + model_len == line_end || p[model_len] == ' ' || p[model_len] == '\t')
                                        model_matched = true;
                        }
                }
                /* Check if line starts with "Compatible:" - only if we matched a machine */
                else if (model_matched && line_end - p >= 11 && strncmp8(p, "Compatible:", 11) == 0) {
                        p = skip_whitespace(p + 11, line_end);

                        /* Bound the value: it ends at the line feed or the end of the section,
                         * whichever comes first, with trailing whitespace trimmed off. */
                        size_t compatible_len = get_prop_end(p, end);
                        if (compatible_len == 0)
                                return 0;

                        *ret_compatible = p;
                        log_debug("Found compatible '%.*s' for model '%s'", (int) compatible_len, p, model);
                        return compatible_len;
                }

                cursor = line_end;
                while (cursor < end && (*cursor == '\n' || *cursor == '\r'))
                        cursor++;
        }

        log_debug("No machdb entry for model '%s'", model);
        return 0;
}

/**
 * pe_machdb() - Match device-tree using /model property and machdb lookup table
 *
 * @fw_dtb:             firmware device-tree
 * @uki_dtb:            device-tree to check
 * @uki_dtb_size:       size of device-tree
 * @section_table:      PE section table to search for .machdb section
 * @n_section_table:    number of entries in the section table
 * @validate_base:      base address for validation and pointer calculations
 *
 * This function implements device-tree matching based on the /model property from
 * the firmware-provided device-tree. It searches for a .machdb section in the PE
 * image, which contains Model: and Compatible: mappings. If the firmware device-tree's
 * /model property matches a Model: entry, the corresponding Compatible: value is compared
 * with the compatible string of the provided DTB.
 *
 * Return: true if this DTB should be used based on model matching, false otherwise.
 */
static bool pe_machdb(
                const void *fw_dtb,
                const void *uki_dtb,
                size_t uki_dtb_size,
                const PeSectionHeader section_table[],
                size_t n_section_table,
                size_t validate_base) {

        assert(uki_dtb);
        assert(section_table || n_section_table == 0);

        static const char *const machdb_section_names[] = { ".machdb", NULL };
        PeSectionVector machdb_section[1] = {};

        pe_locate_sections_internal(
                        section_table,
                        n_section_table,
                        machdb_section_names,
                        validate_base,
                        /* device_table */ NULL,
                        /* device */ NULL,
                        machdb_section);

        if (!PE_SECTION_VECTOR_IS_SET(machdb_section))
                return false;

        const char *machdb = (const char *) SIZE_TO_PTR(validate_base) + machdb_section[0].memory_offset;
        size_t machdb_size = machdb_section[0].memory_size;

        const char *fw_model = devicetree_get_model(fw_dtb);
        if (!fw_model)
                return false;

        const char *compatible;
        size_t compatible_len = machdb_lookup_model(machdb, machdb_size, fw_model, &compatible);
        if (compatible_len == 0)
                return false;

        const char *uki_compat = devicetree_get_compatible(uki_dtb);
        if (!uki_compat)
                return false;

        log_debug("Compatible string from UKI '%s', compatible from machdb '%.*s'",
                        uki_compat, (int) compatible_len, compatible);

        if (strlen8(uki_compat) == compatible_len && strneq8(uki_compat, compatible, compatible_len)) {
                log_debug("selecting device-tree %s based on model", uki_compat);
                return true;
        }

        return false;
}

static bool pe_use_this_dtb(
                const void *dtb,
                size_t dtb_size,
                const void *base,
                const Device *device,
                const PeSectionHeader section_table[],
                size_t n_section_table,
                size_t validate_base,
                size_t section_nb) {

        assert(dtb);

        EFI_STATUS err;

        if (dtb_override == true) {
                err = devicetree_match(dtb, dtb_size);
                if (err == EFI_SUCCESS) {
                        log_debug("found device-tree based on compatible: %s",
                                        devicetree_get_compatible(dtb));
                        return true;
                }
                if (err == EFI_INVALID_PARAMETER)
                        return false;
        }

        /* Check if a firmware dtb exists */
        const void *fw_dtb = find_configuration_table(MAKE_GUID_PTR(EFI_DTB_TABLE));
        if (fw_dtb) {
                /* Try machine matching via machdb if available */
                if (pe_machdb(fw_dtb, dtb, dtb_size, section_table,
                              n_section_table, validate_base))
                        return true;
                return false;
        }

        /* There's nothing to match against if there is no .hwids section */
        if (!device || !base)
                return false;

        const char *compatible = device_get_compatible(base, device);
        if (!compatible)
                return false;

        err = devicetree_match_by_compatible(dtb, dtb_size, compatible);
        if (err == EFI_SUCCESS) {
                log_debug("found device-tree based on HWID: %s",
                                devicetree_get_compatible(dtb));
                return true;
        }
        if (err == EFI_INVALID_PARAMETER)
                log_error_status(err, "Found bad DT blob in PE section %zu", section_nb);
        return false;
}

static void pe_locate_sections_internal(
                const PeSectionHeader section_table[],
                size_t n_section_table,
                const char *const section_names[],
                size_t validate_base,
                const void *device_table,
                const Device *device,
                PeSectionVector sections[]) {

        assert(section_table || n_section_table == 0);
        assert(section_names);
        assert(sections);

        /* Searches for the sections listed in 'sections[]' within the section table. Validates the resulted
         * data. If 'validate_base' is non-zero also takes base offset when loaded into memory into account for
         * checking for overflows. */

        for (size_t i = 0; section_names[i]; i++)
                FOREACH_ARRAY(j, section_table, n_section_table) {

                        if (!pe_section_name_equal((const char*) j->Name, section_names[i]))
                                continue;

                        /* Overflow check: ignore sections that are impossibly large, relative to the file
                         * address for the section. */
                        size_t size_max = SIZE_MAX - j->PointerToRawData;
                        if ((size_t) j->SizeOfRawData > size_max)
                                continue;

                        /* Overflow check: ignore sections that are impossibly large, given the virtual
                         * address for the section */
                        size_max = SIZE_MAX - j->VirtualAddress;
                        if ((size_t) j->VirtualSize > size_max)
                                continue;

                        /* 2nd overflow check: ignore sections that are impossibly large also taking the
                         * loaded base into account. */
                        if (validate_base != 0) {
                                if (validate_base > size_max)
                                        continue;
                                size_max -= validate_base;

                                if (j->VirtualAddress > size_max)
                                        continue;
                        }

                        /* Special handling for .dtbauto sections compared to plain .dtb */
                        if (pe_section_name_equal(section_names[i], ".dtbauto")) {
                                /* .dtbauto sections require validate_base for matching */
                                if (!validate_base)
                                        break;
                                if (!pe_use_this_dtb(
                                                  (const uint8_t *) SIZE_TO_PTR(validate_base) + j->VirtualAddress,
                                                  j->VirtualSize,
                                                  device_table,
                                                  device,
                                                  section_table,
                                                  n_section_table,
                                                  validate_base,
                                                  (PTR_TO_SIZE(j) - PTR_TO_SIZE(section_table)) / sizeof(*j)))
                                        continue;
                        }

                        /* At this time, the sizes and offsets have been validated. Store them away */
                        sections[i] = (PeSectionVector) {
                                .memory_size = j->VirtualSize,
                                .memory_offset = j->VirtualAddress,
                                /* VirtualSize can be bigger than SizeOfRawData when the section requires
                                 * uninitialized data. It can also be smaller than SizeOfRawData when there's
                                 * no need for uninitialized data as SizeOfRawData is aligned to
                                 * FileAlignment and VirtualSize isn't. The actual data that's read from disk
                                 * is the minimum of these two fields. */
                                .file_size = MIN(j->SizeOfRawData, j->VirtualSize),
                                .file_offset = j->PointerToRawData,
                        };

                        /* First matching section wins, ignore the rest */
                        break;
                }
}

static bool looking_for_dtbauto(const char *const section_names[]) {
        assert(section_names);

        for (size_t i = 0; section_names[i]; i++)
                if (pe_section_name_equal(section_names[i], ".dtbauto"))
                        return true;
         return false;
}

void pe_locate_sections(
                const PeSectionHeader section_table[],
                size_t n_section_table,
                const char *const section_names[],
                size_t validate_base,
                PeSectionVector sections[]) {

        if (!looking_for_dtbauto(section_names))
                return pe_locate_sections_internal(
                                  section_table,
                                  n_section_table,
                                  section_names,
                                  validate_base,
                                  /* device_base */ NULL,
                                  /* device */ NULL,
                                  sections);

        /* It doesn't make sense not to provide validate_base here */
        assert(validate_base != 0);

        const void *hwids = NULL;
        const Device *device = NULL;

        if (!firmware_devicetree_exists()) {
                /* Find HWIDs table and search for the current device */
                static const char *const hwid_section_names[] = { ".hwids", NULL };
                PeSectionVector hwids_section[1] = {};

                pe_locate_sections_internal(
                                section_table,
                                n_section_table,
                                hwid_section_names,
                                validate_base,
                                /* device_table */ NULL,
                                /* device */ NULL,
                                hwids_section);

                if (PE_SECTION_VECTOR_IS_SET(hwids_section)) {
                        hwids = (const uint8_t *) SIZE_TO_PTR(validate_base) + hwids_section[0].memory_offset;

                        EFI_STATUS err = chid_match(hwids, hwids_section[0].memory_size, DEVICE_TYPE_DEVICETREE, &device);
                        if (err != EFI_SUCCESS) {
                                if (log_isdebug == true)
                                        log_error_status(err, "HWID matching failed, no DT blob will be selected: %m");
                                hwids = NULL;
                        }
                }
        }

        return pe_locate_sections_internal(
                            section_table,
                            n_section_table,
                            section_names,
                            validate_base,
                            hwids,
                            device,
                            sections);
}

EFI_STATUS pe_kernel_info(const void *base, uint32_t *ret_entry_point, uint64_t *ret_image_base, size_t *ret_size_in_memory) {
        assert(base);

        const DosFileHeader *dos = (const DosFileHeader *) base;
        if (!verify_dos(dos))
                return EFI_LOAD_ERROR;

        const PeFileHeader *pe = (const PeFileHeader *) ((const uint8_t *) base + dos->ExeHeader);
        if (!verify_pe(dos, pe, /* allow_compatibility= */ true))
                return EFI_LOAD_ERROR;

        uint64_t image_base;
        switch (pe->OptionalHeader.Magic) {
        case OPTHDR32_MAGIC:
                image_base = pe->OptionalHeader.ImageBase32;
                break;
        case OPTHDR64_MAGIC:
                image_base = pe->OptionalHeader.ImageBase64;
                break;
        default:
                assert_not_reached();
        }

        /* When allocating we need to also consider the virtual/uninitialized data sections, so parse it out
         * of the SizeOfImage field in the PE header and return it */
        size_t size_in_memory = pe->OptionalHeader.SizeOfImage;

        /* Support for LINUX_INITRD_MEDIA_GUID was added in kernel stub 1.0. */
        if (pe->OptionalHeader.MajorImageVersion < 1)
                return EFI_UNSUPPORTED;

        /* We do not support cross-architecture kernel loading. */
        if (pe->FileHeader.Machine != TARGET_MACHINE_TYPE)
                return EFI_UNSUPPORTED;

        if (ret_entry_point)
                *ret_entry_point = pe->OptionalHeader.AddressOfEntryPoint;
        if (ret_image_base)
                *ret_image_base = image_base;
        if (ret_size_in_memory)
                *ret_size_in_memory = size_in_memory;
        return EFI_SUCCESS;
}

/* https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-data-directories-image-only */
#define BASE_RELOCATION_TABLE_DATA_DIRECTORY_ENTRY 5

/* We do not expect PE inner kernels to have any relocations. However that might be wrong for some
 * architectures, or it might change in the future. If the case of relocation arise, we should transform this
 * function in a function applying the relocations. However for now, since it would not be exercised and
 * would bitrot, we leave it as a check that relocations are never expected.
 */
EFI_STATUS pe_kernel_check_no_relocation(const void *base) {
        assert(base);

        const DosFileHeader *dos = base;
        if (!verify_dos(dos))
                return EFI_LOAD_ERROR;

        const PeFileHeader *pe = (const PeFileHeader *) ((const uint8_t *) base + dos->ExeHeader);
        if (!verify_pe(dos, pe, /* allow_compatibility= */ true))
                return EFI_LOAD_ERROR;

        const PeImageDataDirectory *data_directory;
        switch (pe->OptionalHeader.Magic) {
        case OPTHDR32_MAGIC:
                data_directory = pe->OptionalHeader.DataDirectory32;
                break;
        case OPTHDR64_MAGIC:
                data_directory = pe->OptionalHeader.DataDirectory64;
                break;
        default:
                assert_not_reached();
        }

        if (data_directory[BASE_RELOCATION_TABLE_DATA_DIRECTORY_ENTRY].Size != 0)
                return log_error_status(EFI_LOAD_ERROR, "Inner kernel image contains base relocations, which we do not support.");

        return EFI_SUCCESS;
}

EFI_STATUS pe_section_table_from_base(
                const void *base,
                const PeSectionHeader **ret_section_table,
                size_t *ret_n_section_table) {

        assert(base);
        assert(ret_section_table);
        assert(ret_n_section_table);

        const DosFileHeader *dos = (const DosFileHeader*) base;
        if (!verify_dos(dos))
                return EFI_LOAD_ERROR;

        const PeFileHeader *pe = (const PeFileHeader*) ((const uint8_t*) base + dos->ExeHeader);
        if (!verify_pe(dos, pe, /* allow_compatibility= */ false))
                return EFI_LOAD_ERROR;

        *ret_section_table = (const PeSectionHeader*) ((const uint8_t*) base + section_table_offset(dos, pe));
        *ret_n_section_table = pe->FileHeader.NumberOfSections;

        return EFI_SUCCESS;
}

EFI_STATUS pe_memory_locate_sections(
                const void *base,
                const char *const section_names[],
                PeSectionVector sections[]) {

        EFI_STATUS err;

        assert(base);
        assert(section_names);
        assert(sections);

        const PeSectionHeader *section_table;
        size_t n_section_table;
        err = pe_section_table_from_base(base, &section_table, &n_section_table);
        if (err != EFI_SUCCESS)
                return err;

        pe_locate_sections(
                        section_table,
                        n_section_table,
                        section_names,
                        PTR_TO_SIZE(base),
                        sections);

        return EFI_SUCCESS;
}

EFI_STATUS pe_section_table_from_file(
                EFI_FILE *handle,
                PeSectionHeader **ret_section_table,
                size_t *ret_n_section_table) {

        EFI_STATUS err;
        size_t len;

        assert(handle);
        assert(ret_section_table);
        assert(ret_n_section_table);

        DosFileHeader dos;
        len = sizeof(dos);
        err = handle->Read(handle, &len, &dos);
        if (err != EFI_SUCCESS)
                return err;
        if (len != sizeof(dos) || !verify_dos(&dos))
                return EFI_LOAD_ERROR;

        err = handle->SetPosition(handle, dos.ExeHeader);
        if (err != EFI_SUCCESS)
                return err;

        PeFileHeader pe;
        len = sizeof(pe);
        err = handle->Read(handle, &len, &pe);
        if (err != EFI_SUCCESS)
                return err;
        if (len != sizeof(pe) || !verify_pe(&dos, &pe, /* allow_compatibility= */ false))
                return EFI_LOAD_ERROR;

        DISABLE_WARNING_TYPE_LIMITS;
        if ((size_t) pe.FileHeader.NumberOfSections > SIZE_MAX / sizeof(PeSectionHeader))
                return EFI_OUT_OF_RESOURCES;
        REENABLE_WARNING;
        size_t n_section_table = (size_t) pe.FileHeader.NumberOfSections;
        if (n_section_table * sizeof(PeSectionHeader) > SECTION_TABLE_BYTES_MAX)
                return EFI_OUT_OF_RESOURCES;

        _cleanup_free_ PeSectionHeader *section_table = xnew(PeSectionHeader, n_section_table);
        if (!section_table)
                return EFI_OUT_OF_RESOURCES;

        err = handle->SetPosition(handle, section_table_offset(&dos, &pe));
        if (err != EFI_SUCCESS)
                return err;

        len = n_section_table * sizeof(PeSectionHeader);
        err = handle->Read(handle, &len, section_table);
        if (err != EFI_SUCCESS)
                return err;
        if (len != n_section_table * sizeof(PeSectionHeader))
                return EFI_LOAD_ERROR;

        *ret_section_table = TAKE_PTR(section_table);
        *ret_n_section_table = n_section_table;
        return EFI_SUCCESS;
}
