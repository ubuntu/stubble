/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "devicetree.h"
#include "efi-log.h"
#include "linux.h"
#include "measure.h"
#include "pe.h"
#include "proto/loaded-image.h"
#include "proto/shell-parameters.h"
#include "sbat.h"
#include "secure-boot.h"
#include "string-util-fundamental.h"
#include "uki.h"
#include "util.h"
#include "version.h"

DECLARE_SBAT(SBAT_STUB_SECTION_TEXT);

static bool parse_string(char16_t *p, const char16_t *opt) {
        const size_t opt_len = strlen16(opt);
        if (strncmp16(p, opt, opt_len) == 0 &&
                        (p[opt_len] == ' ' ||
                         p[opt_len] == '\0'))
                return true;
        return false;
}

static void parse_cmdline(char16_t *p) {
        if(p == NULL)
                return;
        while (*p != '\0') {
                if (parse_string(p, L"debug")) {
                        log_isdebug = true;
                } else if (strncmp16(p, L"stubble.dtb_override=",
                                        strlen16(L"stubble.dtb_override=")) == 0) {
                        p += strlen16(L"stubble.dtb_override=");
                        if (parse_string(p, L"true")) {
                                dtb_override = true;
                        } else if (parse_string(p, L"false")) {
                                dtb_override = false;
                        }
                }
                p = strchr16(p, ' ');
                if (p == NULL)
                        return;
                p++;
        }
}

static void process_arguments(
                EFI_HANDLE stub_image,
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                char16_t **ret_cmdline) {

        assert(stub_image);
        assert(loaded_image);
        assert(ret_cmdline);

        /* The UEFI shell registers EFI_SHELL_PARAMETERS_PROTOCOL onto images it runs. This lets us know that
         * LoadOptions starts with the stub binary path which we want to strip off. */
        EFI_SHELL_PARAMETERS_PROTOCOL *shell;
        if (BS->HandleProtocol(stub_image, MAKE_GUID_PTR(EFI_SHELL_PARAMETERS_PROTOCOL), (void **) &shell) != EFI_SUCCESS) {

                /* We also do a superficial check whether first character of passed command line
                 * is printable character (for compat with some Dell systems which fill in garbage?). */
                if (loaded_image->LoadOptionsSize < sizeof(char16_t) || ((const char16_t *) loaded_image->LoadOptions)[0] <= 0x1F)
                        goto nothing;

                /* Not running from EFI shell, use entire LoadOptions. Note that LoadOptions is a void*, so
                 * it could actually be anything! */
                char16_t *c = xstrndup16(loaded_image->LoadOptions, loaded_image->LoadOptionsSize / sizeof(char16_t));
                *ret_cmdline = mangle_stub_cmdline(c);
                return;
        }

        if (shell->Argc <= 1) /* No arguments were provided? Then we fall back to built-in cmdline. */
                goto nothing;

        size_t i = 1;

        if (i < shell->Argc) {
                /* Assemble the command line ourselves without our stub path. */
                *ret_cmdline = xstrdup16(shell->Argv[i++]);
                for (; i < shell->Argc; i++) {
                        _cleanup_free_ char16_t *old = *ret_cmdline;
                        *ret_cmdline = xasprintf("%ls %ls", old, shell->Argv[i]);
                }
        } else
                *ret_cmdline = NULL;

        return;

nothing:
        *ret_cmdline = NULL;
        return;
}

static void install_embedded_devicetree(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const PeSectionVector sections[static _UNIFIED_SECTION_MAX],
                struct devicetree_state *dt_state) {

        EFI_STATUS err;

        assert(loaded_image);
        assert(sections);
        assert(dt_state);

        UnifiedSection section = _UNIFIED_SECTION_MAX;

        /* Use automatically selected DT if available, otherwise go for "normal" one */
        if (PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_DTBAUTO))
                section = UNIFIED_SECTION_DTBAUTO;
        else if (PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_DTB))
                section = UNIFIED_SECTION_DTB;
        else
                return;

        err = devicetree_install_from_memory(
                        dt_state,
                        (const uint8_t*) loaded_image->ImageBase + sections[section].memory_offset,
                        sections[section].memory_size);
        if (err != EFI_SUCCESS)
                log_error_status(err, "Error loading embedded devicetree, ignoring: %m");
}

static EFI_STATUS find_sections(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                PeSectionVector sections[static _UNIFIED_SECTION_MAX]) {

        EFI_STATUS err;

        assert(loaded_image);
        assert(sections);

        const PeSectionHeader *section_table;
        size_t n_section_table;
        err = pe_section_table_from_base(loaded_image->ImageBase, &section_table, &n_section_table);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Unable to locate PE section table: %m");

        /* Get the base sections */
        pe_locate_sections(
                    section_table,
                    n_section_table,
                    unified_sections,
                    /* validate_base= */ PTR_TO_SIZE(loaded_image->ImageBase),
                    sections);

        if (!PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_LINUX))
                return log_error_status(EFI_NOT_FOUND, "Image lacks .linux section.");

        return EFI_SUCCESS;
}

static char16_t* pe_section_to_str16(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const PeSectionVector *section) {

        assert(loaded_image);
        assert(section);

        if (!PE_SECTION_VECTOR_IS_SET(section))
                return NULL;

        return xstrn8_to_16((const char *) loaded_image->ImageBase + section->memory_offset, section->memory_size);
}

static void settle_command_line(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const PeSectionVector sections[static _UNIFIED_SECTION_MAX],
                char16_t **cmdline) {

        assert(loaded_image);
        assert(sections);
        assert(cmdline);

        /* This determines which command line to use. On input *cmdline contains the custom passed in cmdline
         * if there is any.
         *
         * We'll suppress the custom cmdline if we are in Secure Boot mode, and if either there is already
         * a cmdline baked into the UKI or we are in confidential VM mode. */

        if (!isempty(*cmdline)) {
                if (secure_boot_enabled() && PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_CMDLINE))
                        /* Drop the custom cmdline */
                        *cmdline = mfree(*cmdline);
                else {
                        /* Let's measure the passed kernel command line into the TPM. Note that this possibly
                         * duplicates what we already did in the boot menu, if that was already
                         * used. However, since we want the boot menu to support an EFI binary, and want to
                         * this stub to be usable from any boot menu, let's measure things anyway. */
                        bool m = false;
                        (void) tpm_log_load_options(*cmdline, &m);
                }
        }

        /* No cmdline specified? Or suppressed? Then let's take the one from the UKI, if there is any. */
        if (isempty(*cmdline))
                *cmdline = pe_section_to_str16(loaded_image, sections + UNIFIED_SECTION_CMDLINE);
}

static EFI_STATUS run(EFI_HANDLE image) {
        _cleanup_(devicetree_cleanup) struct devicetree_state dt_state = {};
        _cleanup_free_ char16_t *cmdline = NULL;
        struct iovec initrd = {};
        PeSectionVector sections[ELEMENTSOF(unified_sections)] = {};
        EFI_LOADED_IMAGE_PROTOCOL *loaded_image;
        EFI_STATUS err;

        err = BS->HandleProtocol(image, MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL), (void **) &loaded_image);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error getting a LoadedImageProtocol handle: %m");

        /* Pick up the arguments passed to us, and return the rest
         * as potential command line to use. */
        (void) process_arguments(image, loaded_image, &cmdline);

        /* Parse stubble specific bits in the input command line,
         * always do this before deciding to use internal command line. */
        parse_cmdline(cmdline);
        if (log_isdebug == true) {
                log_debug("Stubble configuration:");
                log_debug("debug: enabled");
                log_debug("dtb_override: %s", dtb_override ? "enabled" : "disabled");
        }

        /* Find the sections we want to operate on */
        err = find_sections(loaded_image, sections);
        if (err != EFI_SUCCESS)
                return err;

        /* Let's now check if we actually want to use the command line, measure it if it was passed in. */
        settle_command_line(loaded_image, sections, &cmdline);

        /* Load the base device tree. */
        install_embedded_devicetree(loaded_image, sections, &dt_state);

        /* Find initrd if there is a .initrd section */
        if (PE_SECTION_VECTOR_IS_SET(sections + UNIFIED_SECTION_INITRD))
                initrd = IOVEC_MAKE(
                                (const uint8_t*) loaded_image->ImageBase + sections[UNIFIED_SECTION_INITRD].memory_offset,
                                sections[UNIFIED_SECTION_INITRD].memory_size);

        struct iovec kernel = IOVEC_MAKE(
                        (const uint8_t*) loaded_image->ImageBase + sections[UNIFIED_SECTION_LINUX].memory_offset,
                        sections[UNIFIED_SECTION_LINUX].memory_size);

        err = linux_exec(image, cmdline, &kernel, &initrd);
        return err;
}

DEFINE_EFI_MAIN_FUNCTION(run, "stubble", /* wait_for_debugger= */ false);
