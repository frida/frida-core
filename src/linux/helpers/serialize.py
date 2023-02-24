#!/usr/bin/env python3

from pathlib import Path
import r2pipe
import re
import sys


CODE_PATTERN = re.compile(r"(private const uint8\[\] (\w+)_CODE = {)[^}]+?(};)")
ENTRYPOINT_PATTERN = re.compile(r"(private const uint (\w+)_ENTRYPOINT_OFFSET = )0x[0-9a-f]+(;)")


def main(input_so, output_vala):
    r2 = r2pipe.open(str(input_so))

    sections = r2.cmdj("iSj")
    code_sections = [s for s in sections if s["name"] in [".text", ".rodata"]]
    last_section = code_sections[-1]
    last_end = last_section["vaddr"] + last_section["vsize"]
    base_address = code_sections[0]["vaddr"]
    total_size = last_end - base_address

    r2.cmd(f"s {hex(base_address)}; b {hex(total_size)}")
    code = r2.cmdj("pcj")

    exports = r2.cmdj("iEj")
    entrypoint_offset = exports[0]["vaddr"] - base_address

    identifier_prefix = input_so.stem.upper().replace("-", "_")

    def replace_code(match):
        current_identifier_prefix = match.group(2)
        if current_identifier_prefix != identifier_prefix:
            return match.group(0)

        prefix = match.group(1)
        suffix = match.group(3)

        lines = [prefix]
        indent = "\t\t\t"
        current_line = indent
        offset = 0
        for byte in code:
            if offset > 0:
                if len(current_line) >= 110:
                    lines += [current_line + ","]
                    current_line = indent
                else:
                    current_line += ", "
            current_line += f"0x{byte:02x}"
            offset += 1
        lines += [current_line]
        lines += ["\t\t" + suffix]

        return "\n".join(lines)

    def replace_entrypoint_offset(match):
        current_identifier_prefix = match.group(2)
        if current_identifier_prefix != identifier_prefix:
            return match.group(0)

        prefix = match.group(1)
        suffix = match.group(3)
        return f"{prefix}0x{entrypoint_offset:x}{suffix}"

    current_code = output_vala.read_text(encoding="utf-8")
    updated_code = CODE_PATTERN.sub(replace_code, current_code)
    updated_code = ENTRYPOINT_PATTERN.sub(replace_entrypoint_offset, updated_code)
    output_vala.write_text(updated_code, encoding="utf-8")


if __name__ == "__main__":
    input_so = Path(sys.argv[1])
    output_vala = Path(sys.argv[2])
    main(input_so, output_vala)
