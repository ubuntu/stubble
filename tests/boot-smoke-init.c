/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Minimal /init for the arm64 boot smoke test. It is packed into a tiny
 * initramfs so that a real Linux kernel has something to run. It prints a
 * marker on the serial console and powers the machine off, which makes QEMU
 * exit cleanly.
 */
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <unistd.h>

int main(void) {
        static const char marker[] = "STUBBLE_BOOT_OK\n";
        static const char uart_marker[] = "STUBBLE_BOOT_OK_UART\n";
        ssize_t n;

        n = write(STDOUT_FILENO, marker, sizeof(marker) - 1);
        (void) n;

        (void) mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
        int fd = open("/dev/ttyAMA0", O_WRONLY);
        if (fd >= 0) {
                n = write(fd, uart_marker, sizeof(uart_marker) - 1);
                (void) n;
                (void) close(fd);
        }

        (void) reboot(RB_POWER_OFF);

        for (;;)
                pause();
}
