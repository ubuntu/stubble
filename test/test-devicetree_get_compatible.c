/* SPDX-License-Identifier: LGPL-2.1-or-later */

/**
 * DOC: devicetree_get_compatible() regression test
 *
 * This host-side test exercises devicetree_get_compatible() with one DTB that
 * carries a root compatible property and one DTB that only carries a child node
 * compatible property.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "devicetree.h"

EFI_BOOT_SERVICES *BS;

_noreturn_ void efi_assert(const char *expr, const char *file, unsigned line, const char *function) {
        fprintf(stderr, "%s:%u: %s: Assertion '%s' failed\n", file, line, function, expr);
        abort();
}

int strncmp8(const char *s1, const char *s2, size_t n) {
        return strncmp(s1, s2, n);
}

void *find_configuration_table(const EFI_GUID *guid) {
        (void) guid;
        return NULL;
}

/**
 * read_file() - Read a file into a newly allocated buffer
 * @path: path to the file to load
 * @ret_size: returns the size of the loaded file in bytes
 *
 * Return: a malloc()'d buffer containing the file contents.
 */
static void *read_file(const char *path, size_t *ret_size) {
        FILE *f = fopen(path, "rb");
        void *buffer;
        long size;

        if (!f) {
                fprintf(stderr, "failed to open %s: %s\n", path, strerror(errno));
                exit(EXIT_FAILURE);
        }

        if (fseek(f, 0, SEEK_END) != 0) {
                fprintf(stderr, "failed to seek %s: %s\n", path, strerror(errno));
                fclose(f);
                exit(EXIT_FAILURE);
        }

        size = ftell(f);
        if (size < 0) {
                fprintf(stderr, "failed to size %s: %s\n", path, strerror(errno));
                fclose(f);
                exit(EXIT_FAILURE);
        }

        if (fseek(f, 0, SEEK_SET) != 0) {
                fprintf(stderr, "failed to rewind %s: %s\n", path, strerror(errno));
                fclose(f);
                exit(EXIT_FAILURE);
        }

        buffer = malloc((size_t) size);
        if (!buffer) {
                fprintf(stderr, "failed to allocate %ld bytes\n", size);
                fclose(f);
                exit(EXIT_FAILURE);
        }

        if (fread(buffer, 1, (size_t) size, f) != (size_t) size) {
                fprintf(stderr, "failed to read %s\n", path);
                free(buffer);
                fclose(f);
                exit(EXIT_FAILURE);
        }

        fclose(f);
        *ret_size = (size_t) size;
        return buffer;
}

/**
 * check_compatible() - Validate the root compatible property of a DTB fixture
 * @path: path to the DTB file to inspect
 * @expected: expected root compatible string, or %NULL if no root property
 *            should be found
 *
 * Return: %EXIT_SUCCESS on success, %EXIT_FAILURE on mismatch or parse failure.
 */
static int check_compatible(const char *path, const char *expected) {
        const char *compatible;
        size_t dtb_size;
        void *dtb;

        dtb = read_file(path, &dtb_size);
        if (dtb_size < sizeof(FdtHeader)) {
                fprintf(stderr, "%s is too small to contain an FDT header\n", path);
                free(dtb);
                return EXIT_FAILURE;
        }

        compatible = devicetree_get_compatible(dtb);

        if (!expected) {
                if (compatible) {
                        fprintf(stderr, "%s: expected NULL, got %s\n", path, compatible);
                        free(dtb);
                        return EXIT_FAILURE;
                }

                free(dtb);
                return EXIT_SUCCESS;
        }

        if (!compatible) {
                fprintf(stderr, "%s: devicetree_get_compatible() returned NULL\n", path);
                free(dtb);
                return EXIT_FAILURE;
        }

        if (strcmp(compatible, expected) != 0) {
                fprintf(stderr, "%s: expected %s, got %s\n", path, expected, compatible);
                free(dtb);
                return EXIT_FAILURE;
        }

        free(dtb);
        return EXIT_SUCCESS;
}

/**
 * main() - Exercise devicetree_get_compatible() on positive and negative cases
 * @argc: number of command line arguments
 * @argv: command line arguments, root DTB followed by child-only DTB
 *
 * Return: %EXIT_SUCCESS if both fixtures behave as expected, %EXIT_FAILURE
 * otherwise.
 */
int main(int argc, char **argv) {
        if (argc != 3) {
                fprintf(stderr, "usage: %s ROOT-DTB CHILD-ONLY-DTB\n", argv[0]);
                return EXIT_FAILURE;
        }

        if (check_compatible(argv[1], "stubble,test-root") != EXIT_SUCCESS)
                return EXIT_FAILURE;

        return check_compatible(argv[2], NULL);
}
