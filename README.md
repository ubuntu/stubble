# Stubble

A minimal UEFI kernel boot stub that serves a single purpose:

**Loading machine specific device trees embedded within a
kernel image.**

stubble is compatible with [systemd-stub(7)](https://manpages.ubuntu.com/manpages/plucky/man7/systemd-stub.7.html)
and [ukify(1)](https://manpages.ubuntu.com/manpages/plucky/man1/ukify.1.html).
It is designed to seamlessly integrate with Ubuntu's current bootloader and
boot security model. The resulting kernel image can be signed and verified
and loaded by grub like any other kernel.

Before loading the kernel, the stub generates
[hwids](https://github.com/fwupd/fwupd/blob/main/docs/hwids.md) of the
running machine derived from smbios and compares them to an embedded
lookup table in the .hwids section of the kernel image.
If a match is found it loads the corresponding device tree from the
.dtbauto section before jumping tothe bundled kernel.

## Command-line parameters

- `debug`: Enable debug logging
- `stubble.dtb_override=true/false`: Enable or disable device-tree compat based dtb lookup. The default is `true`.

## Dependencies

```
# apt install python3-pyelftools systemd-ukify
```

## Building

Build the stub:

```
$ make
```

## Device-tree selection

Stubble supports two mechanisms for selecting a device-tree:

If a device-tree has been installed by the firmware as an EFI configuration
table, Stubble compares the ``compatible`` string of that device-tree to the
``compatible`` strings of the appended device-trees. If a match is found, the
pre-installed device-tree is replaced by the one coming with with Stubble.

If no device-tree has been installed by the firmware, properties values (HWIDs)
in the SMBIOS table are used to select one of the appended device-trees. This
mechanism is used for boards that only come with ACPI tables but were the kernel
does not support booting via ACPI.

The HWID based rules must be supplied as a directory with JSON files.

The `.txt` files in hwids/txt are generated with `hwids.py` and
converted to `.json` files by running `hwid2json.py` from the
`hwids` directory.
The `compatible` field of the resulting JSON files has to be
filled in manually.

## Bundling with kernel

Systemd's ukify tool can be used to append a kernel, device-trees in flattened
device tree format (DTB), and hardware ID JSON files to the Stubble stub.

For a simple combined kernel+stubble image bundling a single DTB you can run:

```
$ ukify build --linux=/boot/vmlinuz --stub=stubble.efi --hwids=hwids/json \
--devicetree-auto=/boot/dtb --output=vmlinuz.efi
```

Add more `--device-tree-auto= parameters` for further device-trees.

## Adding new devices

If you would like to add support for a device that please open a pull request
adding the output of `sudo fwupdtool hwids` as a new file in `hwids/txt`.

# Acknowledgements

This project is originally based on
[systemd-stub](https://manpages.ubuntu.com/manpages/plucky/man7/systemd-stub.7.html)
from the systemd project.
The `.dtbauto` feature in systemd was contributed by
[anonymix007](https://github.com/anonymix007/).
It is inspired by the [dtbloader](https://github.com/TravMurav/dtbloader)
project by Nikita Travkin and
[DtbLoader.efi](https://github.com/aarch64-laptops/edk2/tree/dtbloader-app)
from the aarch64-laptops project.
