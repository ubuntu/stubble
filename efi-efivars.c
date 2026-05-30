#include "efi-efivars.h"
#include "util.h"

EFI_STATUS efivar_get_raw(const EFI_GUID *vendor, const char16_t *name, void **ret_data, size_t *ret_size) {
        EFI_STATUS err;

        assert(vendor);
        assert(name);

        size_t size = 0;
        err = RT->GetVariable((char16_t *) name, (EFI_GUID *) vendor, NULL, &size, NULL);
        if (err != EFI_BUFFER_TOO_SMALL)
                return err;

        _cleanup_free_ void *buf = xmalloc(size);
        err = RT->GetVariable((char16_t *) name, (EFI_GUID *) vendor, NULL, &size, buf);
        if (err != EFI_SUCCESS)
                return err;

        if (ret_data)
                *ret_data = TAKE_PTR(buf);
        if (ret_size)
                *ret_size = size;

        return EFI_SUCCESS;
}

EFI_STATUS efivar_get_boolean_u8(const EFI_GUID *vendor, const char16_t *name, bool *ret) {
        _cleanup_free_ uint8_t *b = NULL;
        size_t size;
        EFI_STATUS err;

        assert(vendor);
        assert(name);

        err = efivar_get_raw(vendor, name, (void**) &b, &size);
        if (err != EFI_SUCCESS)
                return err;

        if (ret)
                *ret = *b > 0;

        return EFI_SUCCESS;
}
