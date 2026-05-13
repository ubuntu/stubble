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

OBJS = devicetree.o efi-log.o efi-efivars.o efi-string.o linux.o stub.o util.o uki.o smbios.o initrd.o \
	pe.o chid.o edid.o secure-boot.o sha1.o measure.o

TEST_CFLAGS = -I include -DRELATIVE_SOURCE_PATH="\".\"" -ffreestanding -fshort-wchar -fno-strict-aliasing -O2 -ffunction-sections -fdata-sections
TEST_LDFLAGS = -Wl,--gc-sections

.PHONY: all check clean install

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

install: stubble.efi
	install -m 755 -d ${DESTDIR}${PREFIX}/lib/stubble
	install -m 644 -t ${DESTDIR}${PREFIX}/lib/stubble stubble.efi
	install -m 755 -d ${DESTDIR}${PREFIX}/share/stubble/hwids
	install -m 644 -t ${DESTDIR}${PREFIX}/share/stubble/hwids hwids/json/*

test/data/test-devicetree_get_compatible.dtb: test/data/test-devicetree_get_compatible.dts
	dtc -I dts -O dtb -o $@ $<

test/data/test-devicetree_get_compatible-child-only.dtb: test/data/test-devicetree_get_compatible-child-only.dts
	dtc -I dts -O dtb -o $@ $<

test/test-devicetree_get_compatible: test/test-devicetree_get_compatible.c devicetree.c
	$(CC) $(TEST_CFLAGS) -o $@ $^ $(TEST_LDFLAGS)

check: test/test-devicetree_get_compatible \
	test/data/test-devicetree_get_compatible.dtb \
	test/data/test-devicetree_get_compatible-child-only.dtb
	$< $(word 2,$^) $(word 3,$^)

clean:
	rm -f $(OBJS)
	rm -f stubble
	rm -f stubble.efi
	rm -f test/test-devicetree_get_compatible
	rm -f test/data/*.dtb
