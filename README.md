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

Stubble supports three mechanisms for selecting a device-tree, tried in the
following order:

### 1. HWID-based matching (no firmware device-tree needed)

If no device-tree has been installed by the firmware, hardware ID values (HWIDs)
in the SMBIOS table are used to select one of the appended device-trees. This
mechanism is used for boards that only come with ACPI tables where the kernel
does not support booting via ACPI.

The HWID based rules must be supplied as a directory with JSON files using the
`--hwids` parameter to ukify. The `.txt` files in hwids/txt are generated with
`hwids.py` and converted to `.json` files by running `hwid2json.py` from the
`hwids` directory. The `compatible` field of the resulting JSON files has to be
filled in manually.

### 2. Compatible string matching (pre-installed firmware device-tree needed)

If a device-tree has been installed by the firmware as an EFI configuration
table, Stubble compares the `compatible` string of that device-tree to the
`compatible` strings of the appended device-trees. If a match is found, the
pre-installed device-tree is replaced by the one coming with Stubble.

### 3. Model-based matching via machdb (pre-installed firmware device-tree needed)

If compatible string matching fails and a `.machdb` section is present, Stubble
extracts the `model` property from the firmware-provided device-tree and looks
it up in the machdb database. The machdb maps model strings to device-tree
compatible strings, allowing device-tree selection when the compatible property
doesn't provide a direct match.

The machdb file format is a simple text format:
```
Model: <model-string-1>
Model: <model-string-2>
Compatible: <compatible-string>

Model: <model-string-3>
Compatible: <another-compatible-string>
```

Each `Model:` entry specifies a model string to match (from the firmware
device-tree's `/model` property). Multiple `Model:` entries can precede a
single `Compatible:` entry. The `Compatible:` value must match the compatible
string of one of the appended device-trees. Whitespace after the labels is
ignored.

### 4. Fallback to pre-installed device-tree

If none of the above methods select a device-tree, the firmware-provided
device-tree (if any) remains in use.

## Bundling with kernel

Systemd's ukify tool can be used to append a kernel, device-trees in flattened
device tree format (DTB), hardware ID JSON files, and optionally a machdb file
to the Stubble stub.

For a simple combined kernel+stubble image bundling a single DTB you can run:

```
$ ukify build --linux=/boot/vmlinuz --stub=stubble.efi --hwids=hwids/json \
--devicetree-auto=/boot/dtb --output=vmlinuz.efi
```

Add more `--device-tree-auto=` parameters for further device-trees.

To enable model-based device-tree matching via machdb, add the `--machdb` parameter:

```
$ ukify build --linux=/boot/vmlinuz --stub=stubble.efi --hwids=hwids/json \
--devicetree-auto=/boot/dtb1 --devicetree-auto=/boot/dtb2 \
--machdb=machdb.txt --output=vmlinuz.efi
```

The machdb file should contain Model:/Compatible: mappings as described above.

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
