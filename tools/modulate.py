#!/usr/bin/env python3

import argparse
import os
import re
import shutil
import struct
import subprocess
import sys


elf_format_pattern = re.compile(r"file format ([\w-]+).+architecture: (\w+)", re.DOTALL)
elf_section_pattern = re.compile(r"^\s*\d+\s+([\w\.-]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+2\*\*(\d+)$", re.MULTILINE)
macho_section_pattern = re.compile(r"^\s+sectname\s+(\w+)\n\s+segname\s+(\w+)\n\s+addr\s+0x([0-9a-f]+)\n\s+size\s+0x([0-9a-f]+)\n\s+offset\s+(\d+)$", re.MULTILINE)


def main():
    parser = argparse.ArgumentParser(description="Inspect and manipulate ELF and Mach-O modules.")

    parser.add_argument("input", metavar="/path/to/input/module", type=argparse.FileType("rb"))

    the_whats = ('constructor', 'destructor')
    the_wheres = ('first', 'last')

    parser.add_argument("--move", dest="moves", action='append', nargs=3,
        metavar=("|".join(the_whats), 'function_name', "|".join(the_wheres)), type=str, default=[])
    parser.add_argument("--output", metavar="/path/to/output/module", type=str)

    parser.add_argument("--nm", metavar="/path/to/nm", type=str, default=None)
    parser.add_argument("--objdump", metavar="/path/to/objdump", type=str, default=None)
    parser.add_argument("--otool", metavar="/path/to/otool", type=str, default=None)
    parser.add_argument("--install-name-tool", metavar="/path/to/install_name_tool", type=str, default=None)
    parser.add_argument("--strip", metavar="/path/to/strip", type=str, default=None)

    the_endians = ('big', 'little')
    parser.add_argument("--endian",  metavar=("|".join(the_endians)), type=str, default='little', choices=the_endians)

    args = parser.parse_args()

    if args.input.name == "<stdin>":
        parser.error("reading from stdin is not supported")
    elif len(args.moves) > 0 and args.output is None:
        parser.error("no output file specified")

    for what, function_name, where in args.moves:
        if what not in the_whats:
            parser.error("argument --move: expected {}, got {}".format("|".join(the_whats), what))
        if where not in the_wheres:
            parser.error("argument --move: expected {}, got {}".format("|".join(the_wheres), where))

    toolchain = Toolchain()
    for tool in vars(toolchain).keys():
        path = getattr(args, tool)
        if path is not None:
            setattr(toolchain, tool, path)

    try:
        editor = ModuleEditor(args.input, args.endian, toolchain)
    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    for what, function_name, where in args.moves:
        function_pointers = getattr(editor, what + "s")
        move = getattr(function_pointers, "move_" + where)
        try:
            move(function_name)
        except FunctionNotFound as e:
            using_cxa_atexit = editor.layout.file_format == 'mach-o' and what == 'destructor' and len(e.searched_function_names) == 0
            if not using_cxa_atexit:
                parser.error(e)

    if len(args.moves) == 0:
        editor.dump()
    else:
        editor.save(args.output)


class ModuleEditor(object):
    def __init__(self, module, endian, toolchain):
        self.module = module
        self.endian = endian
        self.toolchain = toolchain

        layout = Layout.from_file(module.name, endian, toolchain)
        self.layout = layout

        sections = layout.sections
        self.constructors = self._read_function_pointer_section(sections.get(layout.constructors_section_name, None), "constructor")
        self.destructors = self._read_function_pointer_section(sections.get(layout.destructors_section_name, None), "destructor")

    def dump(self):
        for i, vector in enumerate([self.constructors, self.destructors]):
            if i > 0:
                print("")
            descriptions = [repr(e) for e in vector.elements]
            if len(descriptions) == 0:
                descriptions.append("(none)")
            print("# {}S\n\t{}".format(vector.label.upper(), "\n\t".join(descriptions)))

    def save(self, destination_path):
        temp_destination_path = destination_path + ".tmp"
        with open(temp_destination_path, "w+b") as destination:
            self.module.seek(0)
            shutil.copyfileobj(self.module, destination)

            self._write_function_pointer_vector(self.constructors, destination)
            self._write_function_pointer_vector(self.destructors, destination)

        if self.layout.file_format == 'mach-o':
            subprocess.check_call([self.toolchain.install_name_tool, "-id", make_darwin_module_name(destination_path), temp_destination_path])

        strip = self.toolchain.strip
        if strip is not None:
            subprocess.check_call([strip, temp_destination_path])

        shutil.move(temp_destination_path, destination_path)

    def _read_function_pointer_section(self, section, label):
        layout = self.layout

        if section is None:
            return FunctionPointerVector(label, None, None, [], layout)

        values = []
        data = self._read_section_data(section)
        pointer_size = layout.pointer_size
        pointer_format = layout.pointer_format
        for i in range(0, len(data), pointer_size):
            (value,) = struct.unpack(pointer_format, data[i:i + pointer_size])
            values.append(value)

        elements = []
        is_macho = layout.file_format == 'mach-o'
        is_arm = layout.arch_name == 'arm'
        is_apple_arm64 = is_macho and layout.arch_name in ('arm64', 'arm64e')
        symbols = layout.symbols
        for value in values:
            if is_arm:
                address = value & ~1
            elif is_apple_arm64:
                # Starting with arm64e, Apple uses the 13 upper bits to encode
                # pointer authentication properties, rebase vs bind, etc.
                top_8_bits     = (value << 13) & 0xff00000000000000
                bottom_43_bits =  value        & 0x000007ffffffffff

                sign_bit_set = (value & (1 << 42)) != 0
                if sign_bit_set:
                    sign_bits = 0x00fff80000000000
                else:
                    sign_bits = 0

                address = top_8_bits | sign_bits | bottom_43_bits
            else:
                address = value

            name = symbols.resolve(address)
            if is_macho and name.startswith("_"):
                name = name[1:]

            elements.append(FunctionPointer(value, name))

        return FunctionPointerVector(label, section.file_offset, section.virtual_address, elements, layout)

    def _read_section_data(self, section):
        self.module.seek(section.file_offset)
        return self.module.read(section.size)

    def _write_function_pointer_vector(self, vector, destination):
        if vector.file_offset is None:
            return

        layout = self.layout
        pointer_size = layout.pointer_size
        pointer_format = layout.pointer_format

        destination.seek(vector.file_offset)

        is_apple_arm64 = layout.file_format == 'mach-o' and layout.arch_name in ('arm64', 'arm64e')
        if is_apple_arm64:
            # Due to Apple's stateful rebasing logic we have to be careful so the upper 13 bits
            # are preserved, and we only reorder the values' lower 51 bits.
            for pointer in vector.elements:
                address = pointer.value

                (old_value,) = struct.unpack(pointer_format, destination.read(pointer_size))
                destination.seek(-pointer_size, os.SEEK_CUR)

                meta_bits = old_value & 0xfff8000000000000

                top_8_bits     = (address & 0xff00000000000000) >> 13
                bottom_43_bits =  address & 0x000007ffffffffff

                new_value = meta_bits | top_8_bits | bottom_43_bits

                destination.write(struct.pack(pointer_format, new_value))
        else:
            for pointer in vector.elements:
                destination.write(struct.pack(pointer_format, pointer.value))

            if layout.file_format == 'elf' and pointer_size == 8:
                pending = {}
                for i, pointer in enumerate(vector.elements):
                    pending[vector.virtual_address + (i * pointer_size)] = pointer

                reloc_section = layout.sections['.rela.dyn']
                reloc_data = self._read_section_data(reloc_section)

                offset = 0
                size = len(reloc_data)
                rela_item_size = 3 * pointer_size

                while offset != size:
                    (r_offset,) = struct.unpack(pointer_format, reloc_data[offset:offset + pointer_size])

                    pointer = pending.pop(r_offset, None)
                    if pointer is not None:
                        r_addend_offset = reloc_section.file_offset + offset + (2 * pointer_size)
                        destination.seek(r_addend_offset)
                        destination.write(struct.pack(pointer_format, pointer.value))

                    offset += rela_item_size

                assert len(pending) == 0


class Toolchain(object):
    def __init__(self):
        self.nm = "nm"
        self.objdump = "objdump"
        self.otool = "otool"
        self.install_name_tool = "install_name_tool"
        self.strip = None

    def __repr__(self):
        return "Toolchain({})".format(", ".join([k + "=" + repr(v) for k, v in vars(self).items()]))


class Layout(object):
    @classmethod
    def from_file(cls, binary_path, endian, toolchain):
        with open(binary_path, "rb") as f:
            magic = f.read(4)
        file_format = 'elf' if magic == b"\x7fELF" else 'mach-o'

        if file_format == 'elf':
            output = subprocess.check_output([toolchain.objdump, "-fh", binary_path]).decode('utf-8')

            elf_format, arch_name = elf_format_pattern.search(output).groups()
            pointer_size = 4 if elf_format.startswith("elf32") else 8

            sections = {}
            for m in elf_section_pattern.finditer(output):
                name, size, vma, lma, file_offset, alignment = m.groups()
                sections[name] = Section(name, int(size, 16), int(vma, 16), int(lma, 16), int(file_offset, 16))
        else:
            output = subprocess.check_output([toolchain.otool, "-l", binary_path]).decode('utf-8')

            arch_name = subprocess.check_output(["file", binary_path]).decode('utf-8').rstrip().split(" ")[-1]
            if arch_name.startswith("arm_"):
                arch_name = 'arm'
            pointer_size = 8 if "64" in arch_name else 4

            sections = {}
            for m in macho_section_pattern.finditer(output):
                section_name, segment_name, address, size, offset = m.groups()
                name = segment_name + "." + section_name
                sections[name] = Section(name, int(size, 16), int(address, 16), None, int(offset, 10))

        symbols = Symbols.from_file(binary_path, pointer_size, toolchain)

        return Layout(file_format, arch_name, endian, pointer_size, sections, symbols)

    def __init__(self, file_format, arch_name, endian, pointer_size, sections, symbols):
        self.file_format = file_format
        self.arch_name = arch_name
        self.endian = endian
        self.pointer_size = pointer_size
        endian_format = "<" if endian == 'little' else ">"
        size_format = "I" if pointer_size == 4 else "Q"
        self.pointer_format = endian_format + size_format

        self.sections = sections
        if file_format == 'elf':
            self.constructors_section_name = ".init_array"
            self.destructors_section_name = ".fini_array"
        else:
            self.constructors_section_name = "__DATA.__mod_init_func"
            self.destructors_section_name = "__DATA.__mod_term_func"

        self.symbols = symbols

    def __repr__(self):
        return "Layout(arch_name={}, endian={}, pointer_size={}, sections=<{} items>, symbols={}".format(
            self.arch_name,
            self.endian,
            self.pointer_size,
            len(self.sections),
            repr(self.symbols))


class Symbols(object):
    @classmethod
    def from_file(cls, binary_path, pointer_size, toolchain):
        items = {}

        for line in subprocess.check_output([toolchain.nm, binary_path]).decode('utf-8').split("\n"):
            tokens = line.split(" ", 2)
            if len(tokens) < 3:
                continue
            raw_address, type, name = tokens
            if type.lower() != 't' or name == "":
                continue
            address = int(raw_address, 16)

            items[address] = name

        return Symbols(items, pointer_size)

    def __init__(self, items, pointer_size):
        self.items = items
        self._pointer_size = pointer_size

    def __repr__(self):
        return "Symbols(items=<{} objects>".format(len(self.items))

    def resolve(self, address):
        result = self.items.get(address, None)
        if result is None:
            raise SymbolNotFound("unable to resolve address 0x{address:0{width}x}".format(address=address, width=self._pointer_size * 2))
        return result


class SymbolNotFound(ValueError):
    def __init__(self, message):
        super().__init__(message)


class Section(object):
    def __init__(self, name, size, virtual_address, load_address, file_offset):
        self.name = name
        self.size = size
        self.virtual_address = virtual_address
        self.load_address = load_address
        self.file_offset = file_offset

    def __repr__(self):
        return "Section({})".format(", ".join([k + "=" + repr(v) for k, v in vars(self).items() if v is not None]))


class FunctionPointerVector(object):
    def __init__(self, label, file_offset, virtual_address, elements, layout):
        self.label = label
        self.file_offset = file_offset
        self.virtual_address = virtual_address
        self.elements = elements

        self._layout = layout

    def __repr__(self):
        return repr(self.elements)

    def move_first(self, name):
        e = self.elements.pop(self._index_of(name))
        self.elements.insert(0, e)

    def move_last(self, name):
        e = self.elements.pop(self._index_of(name))
        self.elements.append(e)

    def _index_of(self, name):
        function_names = [e.name for e in self.elements]

        if len(self.elements) == 0:
            raise FunctionNotFound("no {} functions defined".format(self.label), function_names)

        matches = [i for i, e in enumerate(self.elements) if e.name == name]
        if len(matches) == 0:
            raise FunctionNotFound("no {} named {}; possible options: {}".format(self.label, name, ", ".join(function_names)), function_names)

        return matches[0]


class FunctionNotFound(ValueError):
    def __init__(self, message, searched_function_names):
        super().__init__(message)
        self.searched_function_names = searched_function_names


class FunctionPointer(object):
    def __init__(self, value, name):
        self.value = value
        self.name = name

    def __repr__(self):
        return "FunctionPointer(value=0x{:x}, name=\"{}\")".format(self.value, self.name)


def make_darwin_module_name(path):
    name, ext = os.path.splitext(os.path.basename(path))
    return name.replace("-", " ").title().replace(" ", "")


main()
