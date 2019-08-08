#!/usr/bin/env python3

import argparse
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
    parser.add_argument("--output", metavar="/path/to/output/module", type=argparse.FileType("wb"))

    parser.add_argument("--nm", metavar="/path/to/nm", type=str, default=None)
    parser.add_argument("--objdump", metavar="/path/to/objdump", type=str, default=None)
    parser.add_argument("--otool", metavar="/path/to/otool", type=str, default=None)

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
        editor = ModuleEditor(args.input, toolchain)
    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    for what, function_name, where in args.moves:
        function_pointers = getattr(editor, what + "s")
        move = getattr(function_pointers, "move_" + where)
        try:
            move(function_name)
        except Exception as e:
            parser.error(e)

    if len(args.moves) == 0:
        editor.dump()
    else:
        editor.save(args.output)


class ModuleEditor(object):
    def __init__(self, module, toolchain):
        self.module = module

        layout = Layout.from_file(module.name, toolchain)
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

    def save(self, destination):
        self.module.seek(0)
        shutil.copyfileobj(self.module, destination)

        self._write_function_pointer_vector(self.constructors, destination)
        self._write_function_pointer_vector(self.destructors, destination)

        destination.flush()

    def _read_function_pointer_section(self, section, label):
        layout = self.layout

        if section is None:
            return FunctionPointerVector(label, None, [], layout)

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
        symbols = layout.symbols
        for value in values:
            address = value & ~1 if is_arm else value

            name = symbols.resolve(address)
            if is_macho and name.startswith("_"):
                name = name[1:]

            elements.append(FunctionPointer(value, name))

        return FunctionPointerVector(label, section.file_offset, elements, layout)

    def _read_section_data(self, section):
        self.module.seek(section.file_offset)
        return self.module.read(section.size)

    def _write_function_pointer_vector(self, vector, destination):
        layout = self.layout
        pointer_size = layout.pointer_size
        pointer_format = layout.pointer_format

        destination.seek(vector.file_offset)
        for pointer in vector.elements:
            destination.write(struct.pack(pointer_format, pointer.value))


class Toolchain(object):
    def __init__(self):
        self.nm = "nm"
        self.objdump = "objdump"
        self.otool = "otool"

    def __repr__(self):
        return "Toolchain({})".format(", ".join([k + "=" + repr(v) for k, v in vars(self).items()]))


class Layout(object):
    @classmethod
    def from_file(cls, binary_path, toolchain):
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

        symbols = Symbols.from_file(binary_path, toolchain)

        return Layout(file_format, arch_name, pointer_size, sections, symbols)

    def __init__(self, file_format, arch_name, pointer_size, sections, symbols):
        self.file_format = file_format
        self.arch_name = arch_name
        self.pointer_size = pointer_size
        self.pointer_format = "<" + ("I" if pointer_size == 4 else "Q")

        self.sections = sections
        if file_format == 'elf':
            self.constructors_section_name = ".init_array"
            self.destructors_section_name = ".fini_array"
        else:
            self.constructors_section_name = "__DATA.__mod_init_func"
            self.destructors_section_name = "__DATA.__mod_term_func"

        self.symbols = symbols

    def __repr__(self):
        return "Layout(arch_name={}, pointer_size={}, sections=<{} items>, symbols={}".format(
            self.arch_name,
            self.pointer_size,
            len(self.sections),
            repr(self.symbols))


class Symbols(object):
    @classmethod
    def from_file(cls, binary_path, toolchain):
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

        return Symbols(items)

    def __init__(self, items):
        self.items = items

    def __repr__(self):
        return "Symbols(items=<{} objects>".format(len(self.items))

    def resolve(self, address):
        return self.items[address]


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
    def __init__(self, label, file_offset, elements, layout):
        self.label = label
        self.file_offset = file_offset
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
        if len(self.elements) == 0:
            raise ValueError("no {} functions defined".format(self.label))

        matches = [i for i, e in enumerate(self.elements) if e.name == name]
        if len(matches) == 0:
            function_names = [e.name for e in self.elements]
            raise ValueError("no {} named {}; possible options: {}".format(self.label, name, ", ".join(function_names)))

        return matches[0]


class FunctionPointer(object):
    def __init__(self, value, name):
        self.value = value
        self.name = name

    def __repr__(self):
        return "FunctionPointer(value=0x{:x}, name=\"{}\")".format(self.value, self.name)


main()
