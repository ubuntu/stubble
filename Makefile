# SPDX-License-Identifier: LGPL-2.1-or-later

ARCH?=		$(shell uname -m)
PREFIX?=	/usr/local
MIN_SECTIONS?=2048

include ./Make.defaults

ifeq ($(ARCH),x86_64)
	CFLAGS += -m64 -march=x86-64 -mno-red-zone -mgeneral-regs-only -maccumulate-outgoing-args
	LDFLAGS += -m64
endif
ifeq ($(ARCH),aarch64)
	CFLAGS += -mgeneral-regs-only
endif
ifeq ($(ARCH),riscv64)
	CFLAGS += -march=rv64gc -mabi=lp64d -mcmodel=medany
endif

OBJS = devicetree.o efi-log.o efi-efivars.o efi-string.o linux.o stub.o util.o uki.o smbios.o initrd.o \
	pe.o chid.o edid.o secure-boot.o sha1.o measure.o

.PHONY: all clean install install-kernel-hooks

all: stubble.efi

%.o: %.c
	$(CC) $< $(CFLAGS) -c -o $@

stubble.efi: stubble
	./elf2efi.py --version-major=6 --version-minor=16 \
	    --efi-major=1 --efi-minor=1 --subsystem=10 \
	    --minimum-sections=${MIN_SECTIONS} \
	    --copy-sections=".sbat" $< $@

stubble: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

install: stubble.efi stubblify
	install -m 755 -d ${DESTDIR}${PREFIX}/bin
	install -m 755 -t ${DESTDIR}${PREFIX}/bin stubblify
	install -m 755 -d ${DESTDIR}${PREFIX}/lib/stubble
	install -m 644 -t ${DESTDIR}${PREFIX}/lib/stubble stubble.efi
	install -m 755 -d ${DESTDIR}${PREFIX}/libexec/stubble
	install -m 755 -t ${DESTDIR}${PREFIX}/libexec/stubble hwids/finddtbs.py
	install -m 755 -d ${DESTDIR}${PREFIX}/share/stubble/hwids
	install -m 644 -t ${DESTDIR}${PREFIX}/share/stubble/hwids hwids/json/*
	install -m 644 -t ${DESTDIR}${PREFIX}/share/stubble machdb.txt

install-kernel-hooks:
	install -m 755 -d ${DESTDIR}${PREFIX}/lib/kernel/install.d
	sed 's|^PREFIX=/usr$$|PREFIX=${PREFIX}|' kernel-install/95-stubble-dtb-loader.install \
	    > ${DESTDIR}${PREFIX}/lib/kernel/install.d/95-stubble-dtb-loader.install
	chmod 755 ${DESTDIR}${PREFIX}/lib/kernel/install.d/95-stubble-dtb-loader.install
	install -m 755 -d ${DESTDIR}/etc/kernel/postinst.d
	sed 's|^PREFIX=/usr$$|PREFIX=${PREFIX}|' kernel-postinst.d/50-stubble-dtb-loader \
	    > ${DESTDIR}/etc/kernel/postinst.d/50-stubble-dtb-loader
	chmod 755 ${DESTDIR}/etc/kernel/postinst.d/50-stubble-dtb-loader

clean:
	rm -f $(OBJS)
	rm -f stubble
	rm -f stubble.efi
