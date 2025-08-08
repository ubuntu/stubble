# SPDX-License-Identifier: LGPL-2.1-or-later

include ./Make.defaults

ARCH?=		$(shell uname -m)
PREFIX?=	/usr

ifeq ($(ARCH),x86_64)
	CFLAGS += -m64 -march=x86-64 -mno-red-zone -mgeneral-regs-only -maccumulate-outgoing-args
	LDFLAGS += -m64
endif
ifeq ($(ARCH),aarch64)
	CFLAGS += -mgeneral-regs-only
endif

OBJS = devicetree.o efi-log.o efi-string.o linux.o stub.o util.o uki.o smbios.o initrd.o pe.o \
	chid.o edid.o sha1.o measure.o

.PHONY: all clean install

all: stubble.efi

%.o: %.c
	$(CC) $< $(CFLAGS) -c -o $@

stubble.efi: stubble
	./elf2efi.py --version-major=6 --version-minor=16 \
	    --efi-major=1 --efi-minor=1 --subsystem=10 \
	    --minimum-sections=50 \
	    --copy-sections=".sbat" $< $@

stubble: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

install: stubble.efi
	install -m 755 -d ${DESTDIR}${PREFIX}/lib/stubble
	install -m 644 -t ${DESTDIR}${PREFIX}/lib/stubble stubble.efi
	install -m 755 -d ${DESTDIR}${PREFIX}/share/stubble/hwids
	install -m 644 -t ${DESTDIR}${PREFIX}/share/stubble/hwids hwids/json/*

clean:
	rm -f $(OBJS)
	rm -f stubble
	rm -f stubble.efi
