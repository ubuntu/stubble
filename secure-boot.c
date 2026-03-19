#include "efi-efivars.h"
#include "secure-boot.h"

bool secure_boot_enabled(void) {
        bool secure = false;  /* avoid false maybe-uninitialized warning */
        EFI_STATUS err;

        err = efivar_get_boolean_u8(MAKE_GUID_PTR(EFI_GLOBAL_VARIABLE), u"SecureBoot", &secure);

        return err == EFI_SUCCESS && secure;
}
