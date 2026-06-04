package main

import (
	"bytes"
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"strconv"
	"strings"
)

const coffSymbolSize = 18

// debug/macho cannot read the symbol table of the object the Go linker emits
// on Darwin, so the Mach-O load commands are parsed directly.
var machoMagic64 = []byte{0xcf, 0xfa, 0xed, 0xfe}

const (
	machoHeaderSize    = 32
	machoSymtabCommand = 0x2
)

type span struct {
	lo, hi int
}

func symbolStringTableRanges(data []byte) []span {
	var ranges []span
	for _, member := range archiveMembers(data) {
		object := data[member.lo:member.hi]
		for _, table := range objectStringTableRanges(object) {
			ranges = append(ranges, span{member.lo + table.lo, member.lo + table.hi})
		}
	}
	return ranges
}

func archiveMembers(data []byte) []span {
	var members []span
	pos := len("!<arch>\n")
	for pos+60 <= len(data) {
		header := data[pos : pos+60]

		size, _ := strconv.Atoi(string(bytes.TrimSpace(header[48:58])))

		body := pos + 60
		end := body + size

		lo := body
		name := string(bytes.TrimRight(header[0:16], " "))
		if longNameLength, ok := bsdLongNameLength(name); ok {
			lo += longNameLength
		}

		members = append(members, span{lo, end})

		pos = end + end%2
	}
	return members
}

func bsdLongNameLength(name string) (int, bool) {
	if !strings.HasPrefix(name, "#1/") {
		return 0, false
	}
	length, _ := strconv.Atoi(name[3:])
	return length, true
}

func objectStringTableRanges(object []byte) []span {
	if f, err := elf.NewFile(bytes.NewReader(object)); err == nil {
		return elfStringTableRanges(f)
	}

	if bytes.HasPrefix(object, machoMagic64) {
		return machoStringTableRanges(object)
	}

	if f, err := pe.NewFile(bytes.NewReader(object)); err == nil {
		return coffStringTableRanges(f)
	}

	return nil
}

func elfStringTableRanges(f *elf.File) []span {
	var ranges []span
	for _, s := range f.Sections {
		if s.Type == elf.SHT_STRTAB {
			ranges = append(ranges, span{int(s.Offset), int(s.Offset + s.Size)})
		}
	}
	return ranges
}

func machoStringTableRanges(object []byte) []span {
	commandCount := binary.LittleEndian.Uint32(object[16:])
	offset := machoHeaderSize
	for i := uint32(0); i < commandCount; i++ {
		command := binary.LittleEndian.Uint32(object[offset:])
		commandSize := binary.LittleEndian.Uint32(object[offset+4:])
		if command == machoSymtabCommand {
			lo := int(binary.LittleEndian.Uint32(object[offset+16:]))
			size := int(binary.LittleEndian.Uint32(object[offset+20:]))
			return []span{{lo, lo + size}}
		}
		offset += int(commandSize)
	}
	return nil
}

// COFF keeps names longer than eight bytes in the string table and stores
// shorter ones inline in the symbol record, where an eight-byte name has no
// terminator. Both must be renamed, and the inline ranges are exactly the
// record's name field so a match cannot reach into the record's other fields.
func coffStringTableRanges(f *pe.File) []span {
	symbolTable := int(f.FileHeader.PointerToSymbolTable)
	symbolCount := int(f.FileHeader.NumberOfSymbols)

	stringTable := symbolTable + symbolCount*coffSymbolSize
	ranges := []span{{stringTable + 4, stringTable + 4 + len(f.StringTable)}}

	for i := 0; i < symbolCount; {
		symbol := f.COFFSymbols[i]
		if storedInline(symbol.Name) {
			name := symbolTable + i*coffSymbolSize
			ranges = append(ranges, span{name, name + 8})
		}
		i += 1 + int(symbol.NumberOfAuxSymbols)
	}
	return ranges
}

func storedInline(name [8]uint8) bool {
	return name[0] != 0 || name[1] != 0 || name[2] != 0 || name[3] != 0
}
