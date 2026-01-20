#!/usr/bin/python3

import hashlib
import uuid
import os
import glob

CHID_NAMESPACE = uuid.UUID("70ffd812-4c7f-4c7d-0000-000000000000")

def get_dmi_value(node):
    try:
        path = f"/sys/class/dmi/id/{node}"
        if os.path.exists(path):
            with open(path, 'r') as f:
                return f.read().strip()
    except:
        pass
    return None

def generate_chid(fields):
    if not all(fields):
        return None

    data_string = "&".join(fields)
    encoded_string = data_string.encode('utf-16-le')

    hash_obj = hashlib.sha1(CHID_NAMESPACE.bytes + encoded_string).digest()

    raw = list(hash_obj[:16])
    raw[6] = (raw[6] & 0x0f) | 0x50
    raw[8] = (raw[8] & 0x3f) | 0x80

    return uuid.UUID(bytes=bytes(raw))

def get_edid_info():
    panels = []
    for edid_path in glob.glob("/sys/class/drm/*/edid"):
        try:
            with open(edid_path, "rb") as f:
                blob = f.read()
                panel_id = parse_edid(blob)
                if panel_id:
                    panels.append(panel_id)
        except (IOError, PermissionError):
            continue
    if len(panels) != 1:
        print("Invalid number of monitors, skipping EDID CHID extensions")
        return None
    return panels[0]

def parse_edid(blob):
    if len(blob) < 128:
        return None
    EDID_FIXED_HEADER = b'\x00\xff\xff\xff\xff\xff\xff\x00'
    if blob[0:8] != EDID_FIXED_HEADER:
        return None
    m_id = int.from_bytes(blob[8:10], byteorder='big')
    m_chars = [''] * 3
    for i in range(3):
        letter = (m_id >> (5 * i)) & 0b11111
        if letter > 0b11010: # 26
            return None
        m_chars[2 - i] = chr(letter + ord('A') - 1)
    manuf_name = "".join(m_chars)
    p_code = int.from_bytes(blob[10:12], byteorder='little')
    panel_id = f"{manuf_name}{p_code:04x}"
    return panel_id

def main():
    m = get_dmi_value("sys_vendor")
    f = get_dmi_value("product_family")
    p = get_dmi_value("product_name")
    s = get_dmi_value("product_sku")
    c = get_dmi_value("chassis_type")
    bn = get_dmi_value("board_name")
    bv = get_dmi_value("board_vendor")
    e = get_edid_info()

    smbios_definitions = [
        (3,  [m, f, p, s, bv, bn], "Manufacturer + Family + ProductName + ProductSku + BaseboardManufacturer + BaseboardProduct"),
        (4,  [m, f, p, s],         "Manufacturer + Family + ProductName + ProductSku"),
        (5,  [m, f, p],            "Manufacturer + Family + ProductName"),
        (6,  [m, s, bv, bn],       "Manufacturer + ProductSku + BaseboardManufacturer + BaseboardProduct"),
        (7,  [m, s],               "Manufacturer + ProductSku"),
        (8,  [m, p, bv, bn],       "Manufacturer + ProductName + BaseboardManufacturer + BaseboardProduct"),
        (9,  [m, p],               "Manufacturer + ProductName"),
        (10, [m, f, bv, bn],       "Manufacturer + Family + BaseboardManufacturer + BaseboardProduct"),
        (11, [m, f],               "Manufacturer + Family"),
        (11, [m, c],               "Manufacturer + EnclosureKind"),
        (13, [m, bv, bn],          "Manufacturer + BaseboardManufacturer + BaseboardProduct"),
        (14, [m],                  "Manufacturer"),
        (15, [m, f, p, e],         "Manufacturer + Family + ProductName + EDID"),
        (16, [m, f, e],            "Manufacturer + Family + EDID"),
        (17, [m, s, e],            "Manufacturer + ProductSku + EDID")
    ]

    print(f"Computer Information")
    print("--------------------")
    print(f"Manufacturer: {m}")
    print(f"Family: {f}")
    print(f"ProductName: {p}")
    print(f"ProductSku: {s}")
    print(f"BaseboardManufacturer: {bv}")
    print(f"BaseboardProduct: {bn}")
    print(f"EDID: {e}")

    print(f"Hardware IDs")
    print("------------")
    for level, fields, descr in smbios_definitions:
        chid = generate_chid(fields)
        val = str(chid) if chid else "---"
        if chid:
            print(f"#{level:<4} {{{val}}}\t<- {descr}")

if __name__ == "__main__":
    main()
