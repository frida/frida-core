import base64
import json
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from typing import List


def main(argv):
    go_config = json.loads(base64.b64decode(argv[1]).decode("utf-8"))
    output_dir, priv_dir, go, npm, *inputs = [Path(d).resolve() for d in argv[2:]]

    try:
        build_backend(go_config, inputs, output_dir, priv_dir, go, npm)
    except subprocess.CalledProcessError as e:
        print(e, file=sys.stderr)
        print(
            "Output:\n\t| " + "\n\t| ".join(e.output.strip().split("\n")),
            file=sys.stderr,
        )
        sys.exit(2)
    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)


def build_backend(
    config: dict,
    inputs: List[Path],
    output_dir: Path,
    priv_dir: Path,
    go: Path,
    npm: Path,
):
    base_dir = min(inputs, key=lambda p: len(p.parts)).parent
    for f in inputs:
        dest = priv_dir / f.relative_to(base_dir)
        dest.parent.mkdir(exist_ok=True)
        shutil.copy(f, dest)

    go_sources = [str(f.relative_to(base_dir)) for f in inputs if f.suffix == ".go"]

    def run(*args):
        return subprocess.run(
            args,
            cwd=priv_dir,
            env=config["env"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding="utf-8",
            check=True,
        )

    run(npm, "install")
    # run(npm, "link", "/home/oleavr/src/frida-fs")

    backend_a = priv_dir / "frida-compiler-backend.a"
    backend_h = priv_dir / "frida-compiler-backend.h"

    run(
        go,
        "build",
        "-buildmode=c-archive",
        "-o",
        backend_a.name,
        "-buildvcs=false",
        *config["extra_go_args"],
        *go_sources,
    )

    symbols_to_scramble = detect_conflictful_symbols_in_archive(backend_a, config["nm"])
    scramble_symbols_in_archive(backend_a, symbols_to_scramble, config["ranlib"])

    if (mingw := config.get("mingw")) is not None and (abi := config["abi"]) in {
        "x86",
        "x86_64",
    }:
        prefix = Path(mingw["prefix"])
        ar = config["ar"]

        libmingwex_a = prefix / "lib" / "libmingwex.a"
        if not libmingwex_a.exists():
            libmingwex_a = prefix / mingw["triplet"] / "lib" / "libmingwex.a"

        libgcc_objects = [
            "_chkstk_ms.o",
        ]
        run(*ar, "x", mingw["libcc"], *libgcc_objects)

        gwex_objflavor = "64" if abi == "x86_64" else "32"
        gwex_objects = [
            f"lib{gwex_objflavor}_libmingwex_a-{name}.o"
            for name in [
                "dmisc",
                "gdtoa",
                "gmisc",
                "mingw_fprintf",
                "mingw_pformat",
                "misc",
            ]
        ]
        run(*ar, "x", libmingwex_a, *gwex_objects)

        extra_objects = []
        if abi == "x86_64":
            run(*ar, "x", backend_a.name, "go.o")
            sort_pdata_in_object(Path(priv_dir) / "go.o")
            extra_objects.append("go.o")

        run(*ar, "rs", backend_a.name, *libgcc_objects, *gwex_objects, *extra_objects)

    shutil.copy(priv_dir / backend_a.name, output_dir / backend_a.name)
    shutil.copy(priv_dir / backend_h.name, output_dir / backend_h.name)


def detect_conflictful_symbols_in_archive(
    archive: Path, nm_cmd_array: List[str]
) -> List[str]:
    result = []
    for line in subprocess.run(
        [*nm_cmd_array, str(archive)], capture_output=True, encoding="utf-8", check=True
    ).stdout.splitlines():
        tokens = line.lstrip().split(" ")
        if len(tokens) >= 3 and tokens[1] in {"S", "T"}:
            symbol = tokens[2]
            if all(sub not in symbol for sub in ("/", ".", ":", "frida")):
                result.append(symbol)
    return result


def scramble_symbols_in_archive(
    archive: Path, symbols: List[str], ranlib_cmd_array: List[str]
):
    data = archive.read_bytes()

    for old_sym in symbols:
        new_sym = roll_first_alpha(old_sym)
        data = data.replace(old_sym.encode("ascii"), new_sym.encode("ascii"))

    archive.write_bytes(data)

    subprocess.run([*ranlib_cmd_array, str(archive)], check=True)


def roll_first_alpha(s: str) -> str:
    chars = list(s)
    for i, c in enumerate(chars):
        if c.isalpha():
            if c == "z":
                chars[i] = "a"
            elif c == "Z":
                chars[i] = "A"
            else:
                chars[i] = chr(ord(c) + 1)
            break
    return "".join(chars)


# Work around the Go toolchain's almost-MSVC-compatible object files
# until our patch is merged upstream:
# https://go-review.googlesource.com/c/go/+/678795
def sort_pdata_in_object(object_file: Path):
    data = bytearray(object_file.read_bytes())

    # --- Parse COFF File Header (IMAGE_FILE_HEADER) ---
    # Format: WORD Machine; WORD NumberOfSections;
    #         DWORD TimeDateStamp; DWORD PointerToSymbolTable;
    #         DWORD NumberOfSymbols; WORD SizeOfOptionalHeader;
    #         WORD Characteristics;
    IMAGE_FILE_HEADER_FMT = "<HHLLLHH"
    IMAGE_FILE_HEADER_SIZE = struct.calcsize(IMAGE_FILE_HEADER_FMT)

    if len(data) < IMAGE_FILE_HEADER_SIZE:
        print("Error: File too small to be a valid COFF object", file=sys.stderr)
        return

    (
        machine,
        number_of_sections,
        time_date_stamp,
        pointer_to_symbol_table,
        number_of_symbols,
        size_of_optional_header,
        characteristics,
    ) = struct.unpack(IMAGE_FILE_HEADER_FMT, data[0:IMAGE_FILE_HEADER_SIZE])

    # --- Parse Section Headers to find .pdata ---
    # Each IMAGE_SECTION_HEADER is 40 bytes: Name[8], Misc(VirtualSize), VirtualAddress,
    # SizeOfRawData, PointerToRawData, PointerToRelocations, PointerToLinenumbers,
    # NumberOfRelocations, NumberOfLinenumbers, Characteristics
    SECTION_HEADER_FMT = "<8sLLLLLLHHI"
    SECTION_HEADER_SIZE = struct.calcsize(SECTION_HEADER_FMT)
    section_table_offset = IMAGE_FILE_HEADER_SIZE + size_of_optional_header

    pdata_section_index = None
    pdata_pointer_to_raw = None
    pdata_size_of_raw = None
    pdata_pointer_to_relocs = None
    pdata_number_of_relocs = None

    # Keep all section headers for rewriting relocation entries later if needed
    section_headers = []

    for i in range(number_of_sections):
        offset = section_table_offset + i * SECTION_HEADER_SIZE
        section_data = data[offset : offset + SECTION_HEADER_SIZE]
        (
            name,
            virtual_size,
            virtual_address,
            size_of_raw_data,
            pointer_to_raw_data,
            pointer_to_relocations,
            pointer_to_linenumbers,
            number_of_relocations,
            number_of_linenumbers,
            sec_characteristics,
        ) = struct.unpack(SECTION_HEADER_FMT, section_data)

        section_name = name.rstrip(b"\x00").decode("utf-8")
        section_headers.append(
            {
                "name": section_name,
                "offset": offset,
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "size_of_raw_data": size_of_raw_data,
                "pointer_to_raw_data": pointer_to_raw_data,
                "pointer_to_relocations": pointer_to_relocations,
                "number_of_relocations": number_of_relocations,
            }
        )

        if section_name == ".pdata":
            pdata_section_index = i
            pdata_pointer_to_raw = pointer_to_raw_data
            pdata_size_of_raw = size_of_raw_data
            pdata_pointer_to_relocs = pointer_to_relocations
            pdata_number_of_relocs = number_of_relocations

    if pdata_section_index is None:
        print("Error: No .pdata section found in the object file", file=sys.stderr)
        return

    # --- Parse Symbol Table ---
    # Each IMAGE_SYMBOL is 18 bytes: Name[8], Value (4 bytes), SectionNumber (2 bytes),
    # Type (2 bytes), StorageClass (1 byte), NumberOfAuxSymbols (1 byte)
    SYMBOL_TABLE_ENTRY_SIZE = 18
    symbols = []
    for sym_index in range(number_of_symbols):
        sym_offset = pointer_to_symbol_table + sym_index * SYMBOL_TABLE_ENTRY_SIZE
        entry = data[sym_offset : sym_offset + SYMBOL_TABLE_ENTRY_SIZE]
        if len(entry) < SYMBOL_TABLE_ENTRY_SIZE:
            print("Error: Truncated symbol table entry", file=sys.stderr)
            return
        # Unpack: Name (8s), Value (L), SectionNumber (h), Type (H), StorageClass (B), NumberOfAuxSymbols (B)
        name_bytes, value, section_number, sym_type, storage_class, num_aux = (
            struct.unpack("<8sLhHBB", entry)
        )
        # Decode name: if name_bytes[0:4] are zeros, use string from offset in string table
        if name_bytes[:4] == b"\x00\x00\x00\x00":
            str_table_offset = struct.unpack("<L", name_bytes[4:])[0]
            # String table starts immediately after symbol table: size (4 bytes) + NUL-terminated strings
            str_tab_start = (
                pointer_to_symbol_table + number_of_symbols * SYMBOL_TABLE_ENTRY_SIZE
            )
            # Fetch the name from string table
            str_offset = str_tab_start + str_table_offset
            name_end = data.find(b"\x00", str_offset)
            symbol_name = data[str_offset:name_end].decode("utf-8")
        else:
            symbol_name = name_bytes.partition(b"\x00")[0].decode("utf-8")

        symbols.append(
            {"name": symbol_name, "value": value, "section_number": section_number}
        )

    # --- Read original .pdata section raw data ---
    pdata_data = data[pdata_pointer_to_raw : pdata_pointer_to_raw + pdata_size_of_raw]
    if len(pdata_data) % 12 != 0:
        print("Error: .pdata size is not a multiple of 12 bytes", file=sys.stderr)
        return
    num_entries = len(pdata_data) // 12

    # --- Read relocation entries for .pdata ---
    # Each IMAGE_RELOCATION is 10 bytes: VirtualAddress (4), SymbolTableIndex (4), Type (2)
    RELOC_ENTRY_SIZE = 10
    reloc_entries = []
    reloc_table_start = pdata_pointer_to_relocs
    for rindex in range(pdata_number_of_relocs):
        reloff = reloc_table_start + rindex * RELOC_ENTRY_SIZE
        entry = data[reloff : reloff + RELOC_ENTRY_SIZE]
        if len(entry) < RELOC_ENTRY_SIZE:
            print("Error: Truncated relocation entry", file=sys.stderr)
            return
        va, sym_index, rtype = struct.unpack("<LLH", entry)
        reloc_entries.append(
            {"virtual_address": va, "symbol_index": sym_index, "type": rtype}
        )

    # There should be 3 relocations per .pdata entry
    if len(reloc_entries) != num_entries * 3:
        print(
            "Warning: Expected {} relocations but found {}".format(
                num_entries * 3, len(reloc_entries)
            ),
            file=sys.stderr,
        )

    # --- Associate each entry with its relocations and sorting key ---
    entries = []
    for i in range(num_entries):
        entry_bytes = pdata_data[i * 12 : (i + 1) * 12]
        entry_relocs = reloc_entries[i * 3 : i * 3 + 3]

        # Sorting key: use symbol.Value of first relocation"s symbol index
        sym_idx = entry_relocs[0]["symbol_index"]
        if sym_idx < 0 or sym_idx >= number_of_symbols:
            key = 0
        else:
            key = symbols[sym_idx]["value"]

        entries.append({"entry_bytes": entry_bytes, "relocs": entry_relocs, "key": key})

    # --- Sort entries by computed key ---
    entries.sort(key=lambda x: x["key"])

    # --- Build new .pdata data buffer ---
    sorted_pdata = bytearray()
    for e in entries:
        sorted_pdata.extend(e["entry_bytes"])

    # --- Build new relocation table buffer ---
    new_reloc_buf = bytearray()
    for new_i, e in enumerate(entries):
        for reloc in e["relocs"]:
            field_offset = reloc["virtual_address"] % 12
            new_va = new_i * 12 + field_offset
            packed = struct.pack("<LLH", new_va, reloc["symbol_index"], reloc["type"])
            new_reloc_buf.extend(packed)

    # --- Write back sorted .pdata and new relocations into data buffer ---
    # Replace .pdata raw data
    data[pdata_pointer_to_raw : pdata_pointer_to_raw + pdata_size_of_raw] = sorted_pdata
    # Replace relocation entries
    data[pdata_pointer_to_relocs : pdata_pointer_to_relocs + len(new_reloc_buf)] = (
        new_reloc_buf
    )

    # --- Emit the fixed object file ---
    object_file.write_bytes(data)


if __name__ == "__main__":
    main(sys.argv)
