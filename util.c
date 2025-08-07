/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "util.h"
#include "version.h"

void free(void *p) {
        if (!p)
                return;

        /* Debugging an invalid free requires trace logging to find the call site or a debugger attached. For
         * release builds it is not worth the bother to even warn when we cannot even print a call stack. */
#ifdef EFI_DEBUG
        assert_se(BS->FreePool(p) == EFI_SUCCESS);
#else
        (void) BS->FreePool(p);
#endif
}

static bool shall_be_whitespace(char16_t c) {
        return c <= 0x20U || c == 0x7FU; /* All control characters + space */
}

char16_t* mangle_stub_cmdline(char16_t *cmdline) {
        if (!cmdline)
                return cmdline;

        /* Skip initial whitespace */
        const char16_t *p = cmdline;
        while (*p != 0 && shall_be_whitespace(*p))
                p++;

        /* Turn inner control characters into proper spaces */
        char16_t *e = cmdline;
        for (char16_t *q = cmdline; *p != 0; p++) {
                if (shall_be_whitespace(*p)) {
                        *(q++) = ' ';
                        continue;
                }

                *(q++) = *p;
                e = q; /* remember last non-whitespace char */
        }

        /* Chop off trailing whitespace */
        *e = 0;
        return cmdline;
}

__attribute__((noinline)) void notify_debugger(const char *identity, volatile bool wait) {
#ifdef EFI_DEBUG
        printf("%s@%p %s\n", identity, __executable_start, GIT_VERSION);
        if (wait)
                printf("Waiting for debugger to attach...\n");

        /* This is a poor programmer's breakpoint to wait until a debugger
         * has attached to us. Just "set variable wait = 0" or "return" to continue. */
        while (wait)
                /* Prefer asm based stalling so that gdb has a source location to present. */
#  if defined(__i386__) || defined(__x86_64__)
                asm volatile("pause");
#  elif defined(__aarch64__)
                asm volatile("wfi");
#  else
                BS->Stall(5000);
#  endif
#endif
}

void *find_configuration_table(const EFI_GUID *guid) {
        for (size_t i = 0; i < ST->NumberOfTableEntries; i++)
                if (efi_guid_equal(&ST->ConfigurationTable[i].VendorGuid, guid))
                        return ST->ConfigurationTable[i].VendorTable;

        return NULL;
}

void *xmalloc(size_t size) {
        void *p = NULL;
        assert_se(BS->AllocatePool(EfiLoaderData, size, &p) == EFI_SUCCESS);
        return p;
}
