package patterns

import (
	"fmt"
	"math"
	"math/big"
	"math/bits"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type builtin struct {
	arity int
	call  func(f *frame, args []runtimeValue) (runtimeValue, error)
	js    string
}

const variadic = -1

var builtins = map[string]*builtin{}

func defineBuiltin(name string, arity int, js string, call func(f *frame, args []runtimeValue) (runtimeValue, error)) {
	builtins[name] = &builtin{arity: arity, call: call, js: js}
}

func init() {
	defineMemoryBuiltins()
	defineCoreBuiltins()
	defineOutputBuiltins()
	defineStringBuiltins()
	defineCharacterBuiltins()
	defineMathBuiltins()
	defineTimeBuiltins()
	defineLimitBuiltins()
	defineHashBuiltins()
}

func (f *frame) builtin(call *Builtin) (runtimeValue, error) {
	arguments := make([]runtimeValue, len(call.Arguments))
	for i, argument := range call.Arguments {
		result, err := f.eval(argument)
		if err != nil {
			return nil, err
		}
		arguments[i] = result
	}
	return builtins[call.Name].call(f, arguments)
}

func defineMemoryBuiltins() {
	defineBuiltin("std::mem::create_section", 1, "$std_mem_create_section", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		return int64(f.decoder.createSection(display(args[0])).id), nil
	})
	defineBuiltin("std::mem::delete_section", 1, "$std_mem_delete_section", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		target, err := f.sectionArgument(args[0])
		if err != nil {
			return nil, err
		}
		if target.id == 0 {
			return nil, fmt.Errorf("the main section cannot be deleted")
		}
		f.decoder.sections[target.id] = nil
		return nil, nil
	})
	defineBuiltin("std::mem::get_section_size", 1, "$std_mem_get_section_size", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		target, err := f.sectionArgument(args[0])
		if err != nil {
			return nil, err
		}
		return int64(len(target.data)), nil
	})
	defineBuiltin("std::mem::set_section_size", 2, "$std_mem_set_section_size", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		target, err := f.sectionArgument(args[0])
		if err != nil {
			return nil, err
		}
		size, err := toInt(args[1])
		if err != nil {
			return nil, err
		}
		if target.id == 0 || size < 0 {
			return nil, fmt.Errorf("the section cannot be resized")
		}
		target.data = target.data[:min(len(target.data), int(size))]
		target.ensure(int(size))
		f.decoder.refresh(target)
		return nil, nil
	})
	for _, name := range []string{"std::mem::copy_to_section", "std::mem::copy_section_to_section"} {
		defineBuiltin(name, 5, "$std_mem_copy_section_to_section", func(f *frame, args []runtimeValue) (runtimeValue, error) {
			from, err := f.sectionArgument(args[0])
			if err != nil {
				return nil, err
			}
			to, err := f.sectionArgument(args[2])
			if err != nil {
				return nil, err
			}
			var bytes []byte
			f.decoder.within(from, func() { bytes, err = f.readBytesAt(0, args[1], args[4]) })
			if err != nil {
				return nil, err
			}
			return nil, f.copyToSection(to, args[3], bytes)
		})
	}
	defineBuiltin("std::mem::copy_value_to_section", 3, "$std_mem_copy_value_to_section", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		to, err := f.sectionArgument(args[1])
		if err != nil {
			return nil, err
		}
		if text, isString := args[0].(string); isString {
			return nil, f.copyToSection(to, args[2], []byte(text))
		}
		node, isPattern := args[0].(*DecodedValue)
		if !isPattern || node.Size == nil {
			return nil, fmt.Errorf("copy_value_to_section expects a pattern")
		}
		source := f.decoder.sections[node.Section]
		if node.Offset+*node.Size > len(source.data) {
			return nil, errTruncated
		}
		return nil, f.copyToSection(to, args[2], source.data[node.Offset:node.Offset+*node.Size])
	})
	defineBuiltin("std::mem::eof", 0, "$std_mem_eof", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		return f.cursorOwner().cursor >= len(f.decoder.active.data), nil
	})
	defineBuiltin("std::mem::size", 0, "$std_mem_size", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		return int64(len(f.decoder.active.data)), nil
	})
	defineBuiltin("std::mem::base_address", 0, "$std_mem_base_address", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		return int64(0), nil
	})
	defineBuiltin("std::mem::reached", 1, "$std_mem_reached", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		address, err := toInt(args[0])
		if err != nil {
			return nil, err
		}
		owner := f.cursorOwner()
		return int64(owner.cursor-owner.base) >= address, nil
	})
	defineBuiltin("std::mem::align_to", 2, "$std_mem_align_to", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		alignment, err := toInt(args[0])
		if err != nil {
			return nil, err
		}
		value, err := toInt(args[1])
		if err != nil {
			return nil, err
		}
		if alignment <= 0 {
			return value, nil
		}
		return int64(alignUp(int(value), int(alignment))), nil
	})
	defineBuiltin("std::mem::read_unsigned", variadic, "$std_mem_read_unsigned", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		return f.readInteger(args, false)
	})
	defineBuiltin("std::mem::read_signed", variadic, "$std_mem_read_signed", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		return f.readInteger(args, true)
	})
	defineBuiltin("std::mem::read_string", 2, "$std_mem_read_string", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		bytes, err := f.readBytes(args[0], args[1])
		if err != nil {
			return nil, err
		}
		return string(bytes), nil
	})
	defineBuiltin("std::mem::find_sequence", variadic, "$std_mem_find_sequence", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		return f.findSequence(args[0], int64(0), int64(len(f.decoder.active.data)), args[1:])
	})
	defineBuiltin("std::mem::find_sequence_in_range", variadic, "$std_mem_find_sequence_in_range", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		return f.findSequence(args[0], args[1], args[2], args[3:])
	})
	defineBuiltin("std::mem::find_string", 2, "$std_mem_find_string", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		return f.findBytes(args[0], int64(0), int64(len(f.decoder.active.data)), []byte(display(args[1])))
	})
	defineBuiltin("std::mem::find_string_in_range", 4, "$std_mem_find_string_in_range", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		return f.findBytes(args[0], args[1], args[2], []byte(display(args[3])))
	})
}

func (f *frame) copyToSection(to *section, addressValue runtimeValue, bytes []byte) error {
	address, err := toInt(addressValue)
	if err != nil {
		return err
	}
	if to.id == 0 {
		return fmt.Errorf("the main section is read-only")
	}
	f.decoder.write(to, int(address), append([]byte{}, bytes...))
	return nil
}

func (f *frame) readInteger(args []runtimeValue, signed bool) (runtimeValue, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("expected an address and a size")
	}
	var bytes []byte
	var err error
	if len(args) > 3 {
		target, sectionErr := f.sectionArgument(args[3])
		if sectionErr != nil {
			return nil, sectionErr
		}
		f.decoder.within(target, func() { bytes, err = f.readBytesAt(0, args[0], args[1]) })
	} else {
		bytes, err = f.readBytes(args[0], args[1])
	}
	if err != nil {
		return nil, err
	}
	kind := integerKindOfSize(len(bytes), signed)
	order := NativeOrder
	if len(args) > 2 {
		endian, err := toInt(args[2])
		if err != nil {
			return nil, err
		}
		order = map[int64]ByteOrder{1: BigEndian, 2: LittleEndian}[endian]
	}
	return f.decoder.rawValue(&Primitive{Kind: kind, Order: order}, bytes), nil
}

func (f *frame) readBytes(addressValue runtimeValue, sizeValue runtimeValue) ([]byte, error) {
	return f.readBytesAt(f.cursorOwner().base, addressValue, sizeValue)
}

func (f *frame) readBytesAt(base int, addressValue runtimeValue, sizeValue runtimeValue) ([]byte, error) {
	address, err := toInt(addressValue)
	if err != nil {
		return nil, err
	}
	size, err := toInt(sizeValue)
	if err != nil {
		return nil, err
	}
	return f.decoder.bytesOrZeros(base+int(address), int(size)), nil
}

func (f *frame) sectionArgument(v runtimeValue) (*section, error) {
	id, err := toInt(v)
	if err != nil {
		return nil, err
	}
	switch id {
	case -1:
		return f.decoder.active, nil
	case -2:
		return nil, fmt.Errorf("the pattern-local section cannot be accessed")
	}
	return f.decoder.section(id)
}

func (f *frame) findSequence(occurrenceValue runtimeValue, from runtimeValue, to runtimeValue, pattern []runtimeValue) (runtimeValue, error) {
	needle := make([]byte, len(pattern))
	for i, element := range pattern {
		number, err := toInt(element)
		if err != nil {
			return nil, err
		}
		needle[i] = byte(number)
	}
	return f.findBytes(occurrenceValue, from, to, needle)
}

func (f *frame) findBytes(occurrenceValue runtimeValue, fromValue runtimeValue, toValue runtimeValue, needle []byte) (runtimeValue, error) {
	occurrence, err := toInt(occurrenceValue)
	if err != nil {
		return nil, err
	}
	from, err := toInt(fromValue)
	if err != nil {
		return nil, err
	}
	to, err := toInt(toValue)
	if err != nil {
		return nil, err
	}
	base := f.cursorOwner().base
	data := f.decoder.active.data
	start := max(0, min(base+int(from), len(data)))
	end := max(start, min(base+int(to), len(data)))
	haystack := data[start:end]
	offset := 0
	for {
		index := strings.Index(string(haystack[offset:]), string(needle))
		if index == -1 {
			return int64(-1), nil
		}
		if occurrence == 0 {
			return int64(start + offset + index - base), nil
		}
		occurrence--
		offset += index + 1
	}
}

func defineCoreBuiltins() {
	defineBuiltin("std::core::array_index", 0, "$std_core_array_index", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		return int64(f.cursorOwner().arrayIndex), nil
	})
	defineBuiltin("std::core::member_count", 1, "$std_core_member_count", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		if elements, isArray := args[0].([]runtimeValue); isArray {
			return int64(len(elements)), nil
		}
		node, isPattern := args[0].(*DecodedValue)
		if !isPattern {
			return nil, fmt.Errorf("member_count expects a pattern")
		}
		if node.Count != nil {
			return int64(*node.Count), nil
		}
		return int64(len(node.Fields)), nil
	})
	defineBuiltin("std::core::has_member", 2, "$std_core_has_member", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		node, isPattern := args[0].(*DecodedValue)
		if !isPattern {
			return nil, fmt.Errorf("has_member expects a pattern")
		}
		name := display(args[1])
		for _, field := range node.Fields {
			if field.Name == name {
				return true, nil
			}
		}
		return false, nil
	})
	defineBuiltin("std::core::set_display_name", 2, "$std_core_set_display_name", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		node, isPattern := args[0].(*DecodedValue)
		if !isPattern {
			return nil, fmt.Errorf("set_display_name expects a pattern")
		}
		node.DisplayName = display(args[1])
		return nil, nil
	})
	defineBuiltin("std::core::formatted_value", 1, "$std_core_formatted_value", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		if node, isPattern := args[0].(*DecodedValue); isPattern {
			node.formatNow()
			if node.Formatted != "" {
				return node.Formatted, nil
			}
			return display(node.raw), nil
		}
		return display(args[0]), nil
	})
	defineBuiltin("std::core::set_endian", 1, "$std_core_set_endian", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		endian, err := toInt(args[0])
		if err != nil {
			return nil, err
		}
		f.decoder.littleEndian = endian != 1
		return nil, nil
	})
}

func defineOutputBuiltins() {
	defineBuiltin("std::format", variadic, "$std_format", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		if len(args) == 0 {
			return nil, fmt.Errorf("std::format expects a format string")
		}
		return format(display(args[0]), args[1:]), nil
	})
	defineBuiltin("std::print", variadic, "$std_print", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		if len(args) == 0 {
			return nil, fmt.Errorf("std::print expects a format string")
		}
		f.decoder.log = append(f.decoder.log, format(display(args[0]), args[1:]))
		return nil, nil
	})
	defineBuiltin("std::assert", 2, "$std_assert", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		passed, err := truthyValue(args[0])
		if err != nil {
			return nil, err
		}
		if !passed {
			return nil, fmt.Errorf("assertion failed: %s", display(args[1]))
		}
		return nil, nil
	})
	defineBuiltin("std::error", 1, "$std_error", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		return nil, fmt.Errorf("%s", display(args[0]))
	})
	defineBuiltin("std::warning", 1, "$std_warning", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		f.decoder.log = append(f.decoder.log, display(args[0]))
		return nil, nil
	})
	defineBuiltin("std::assert_warn", 2, "$std_assert_warn", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		passed, err := truthyValue(args[0])
		if err != nil {
			return nil, err
		}
		if !passed {
			f.decoder.log = append(f.decoder.log, display(args[1]))
		}
		return nil, nil
	})
}

func defineStringBuiltins() {
	defineBuiltin("std::string::length", 1, "$std_string_length", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		return int64(len([]rune(display(args[0])))), nil
	})
	defineBuiltin("std::string::at", 2, "$std_string_at", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		runes := []rune(display(args[0]))
		index, err := toInt(args[1])
		if err != nil {
			return nil, err
		}
		if index < 0 || index >= int64(len(runes)) {
			return nil, fmt.Errorf("index %d is out of range", index)
		}
		return string(runes[index]), nil
	})
	defineBuiltin("std::string::substr", 3, "$std_string_substr", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		runes := []rune(display(args[0]))
		start, err := toInt(args[1])
		if err != nil {
			return nil, err
		}
		count, err := toInt(args[2])
		if err != nil {
			return nil, err
		}
		start = max(0, min(start, int64(len(runes))))
		end := max(start, min(start+count, int64(len(runes))))
		return string(runes[start:end]), nil
	})
	defineBuiltin("std::string::contains", 2, "$std_string_contains", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		return strings.Contains(display(args[0]), display(args[1])), nil
	})
	defineBuiltin("std::string::starts_with", 2, "$std_string_starts_with", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		return strings.HasPrefix(display(args[0]), display(args[1])), nil
	})
	defineBuiltin("std::string::ends_with", 2, "$std_string_ends_with", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		return strings.HasSuffix(display(args[0]), display(args[1])), nil
	})
	defineBuiltin("std::string::to_string", 1, "$std_string_to_string", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		return display(args[0]), nil
	})
	defineBuiltin("std::string::to_upper", 1, "$std_string_to_upper", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		return strings.ToUpper(display(args[0])), nil
	})
	defineBuiltin("std::string::to_lower", 1, "$std_string_to_lower", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		return strings.ToLower(display(args[0])), nil
	})
	defineBuiltin("std::string::reverse", 1, "$std_string_reverse", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		runes := []rune(display(args[0]))
		for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
			runes[i], runes[j] = runes[j], runes[i]
		}
		return string(runes), nil
	})
	defineBuiltin("std::string::replace", 3, "$std_string_replace", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		return strings.ReplaceAll(display(args[0]), display(args[1]), display(args[2])), nil
	})
	defineBuiltin("std::string::parse_int", 2, "$std_string_parse_int", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		base, err := toInt(args[1])
		if err != nil {
			return nil, err
		}
		number, err := strconv.ParseInt(strings.TrimSpace(display(args[0])), int(base), 64)
		if err != nil {
			return nil, fmt.Errorf("%q is not a number", display(args[0]))
		}
		return number, nil
	})
	defineBuiltin("std::string::parse_float", 1, "$std_string_parse_float", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		number, err := strconv.ParseFloat(strings.TrimSpace(display(args[0])), 64)
		if err != nil {
			return nil, fmt.Errorf("%q is not a number", display(args[0]))
		}
		return number, nil
	})
}

func defineCharacterBuiltins() {
	classes := map[string]func(rune) bool{
		"isprint":  unicode.IsPrint,
		"isgraph":  func(c rune) bool { return unicode.IsPrint(c) && c != ' ' },
		"isdigit":  unicode.IsDigit,
		"isalpha":  unicode.IsLetter,
		"isalnum":  func(c rune) bool { return unicode.IsLetter(c) || unicode.IsDigit(c) },
		"isspace":  unicode.IsSpace,
		"isupper":  unicode.IsUpper,
		"islower":  unicode.IsLower,
		"iscntrl":  unicode.IsControl,
		"ispunct":  unicode.IsPunct,
		"isxdigit": func(c rune) bool { _, ok := digitValue(byte(c), 16); return c < 128 && ok },
	}
	for name, class := range classes {
		defineBuiltin("std::ctype::"+name, 1, "$std_ctype_"+name, func(f *frame, args []runtimeValue) (runtimeValue, error) {
			return class(characterOf(args[0])), nil
		})
	}
}

func characterOf(v runtimeValue) rune {
	if text, isString := v.(string); isString {
		for _, c := range text {
			return c
		}
		return 0
	}
	number, _ := toInt(v)
	return rune(number)
}

func defineMathBuiltins() {
	unary := map[string]func(float64) float64{
		"floor": math.Floor, "ceil": math.Ceil, "round": math.Round, "sqrt": math.Sqrt,
		"sin": math.Sin, "cos": math.Cos, "tan": math.Tan, "exp": math.Exp,
		"log": math.Log, "log2": math.Log2, "log10": math.Log10,
	}
	for name, function := range unary {
		defineBuiltin("std::math::"+name, 1, "$std_math_"+name, func(f *frame, args []runtimeValue) (runtimeValue, error) {
			number, err := toFloat(args[0])
			if err != nil {
				return nil, err
			}
			return function(number), nil
		})
	}
	defineBuiltin("std::math::pow", 2, "$std_math_pow", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		base, err := toFloat(args[0])
		if err != nil {
			return nil, err
		}
		exponent, err := toFloat(args[1])
		if err != nil {
			return nil, err
		}
		return math.Pow(base, exponent), nil
	})
	defineBuiltin("std::math::min", 2, "$std_math_min", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		return extremum(false, args[0], args[1])
	})
	defineBuiltin("std::math::max", 2, "$std_math_max", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		return extremum(true, args[0], args[1])
	})
	defineBuiltin("std::math::abs", 1, "$std_math_abs", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		if number, isFloat := args[0].(float64); isFloat {
			return math.Abs(number), nil
		}
		number, err := toInt(args[0])
		if err != nil {
			return nil, err
		}
		if number < 0 {
			return -number, nil
		}
		return number, nil
	})
	defineBuiltin("std::math::factorial", 1, "$std_math_factorial", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		number, err := toInt(args[0])
		if err != nil {
			return nil, err
		}
		result := int64(1)
		for i := int64(2); i <= number; i++ {
			result *= i
		}
		return result, nil
	})
	defineBuiltin("std::math::accumulate", variadic, "$std_math_accumulate", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		if len(args) < 3 {
			return nil, fmt.Errorf("accumulate expects a start, an end and a value size")
		}
		var bounds [3]int64
		for i := range bounds {
			value, err := toInt(patternInteger(args[i]))
			if err != nil {
				return nil, err
			}
			bounds[i] = value
		}
		start, end, width := bounds[0], bounds[1], bounds[2]
		if width <= 0 || width > 8 {
			return nil, fmt.Errorf("accumulate expects a value size between 1 and 8")
		}
		var sum runtimeValue = int64(0)
		for address := start; address+width <= end; address += width {
			bytes, err := f.readBytes(address, width)
			if err != nil {
				break
			}
			total, err := combine("+", sum, f.decoder.rawValue(&Primitive{Kind: integerKindOfSize(len(bytes), false)}, bytes))
			if err != nil {
				return nil, err
			}
			sum = total
		}
		return sum, nil
	})
}

func defineTimeBuiltins() {
	defineBuiltin("std::time::epoch", 0, "$std_time_epoch", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		return time.Now().Unix(), nil
	})
	defineBuiltin("std::time::to_utc", 1, "$std_time_to_utc", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		seconds, err := toInt(args[0])
		if err != nil {
			return nil, err
		}
		return packTime(time.Unix(seconds, 0).UTC(), f.decoder.littleEndian), nil
	})
	defineBuiltin("std::time::to_local", 1, "$std_time_to_local", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		seconds, err := toInt(args[0])
		if err != nil {
			return nil, err
		}
		return packTime(time.Unix(seconds, 0).Local(), f.decoder.littleEndian), nil
	})
	defineBuiltin("std::time::to_epoch", 1, "$std_time_to_epoch", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		fields, err := unpackTime(args[0], f.decoder.littleEndian)
		if err != nil {
			return nil, err
		}
		return fields.moment(time.Local).Unix(), nil
	})
	defineBuiltin("std::time::format", 2, "$std_time_format", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		fields, err := unpackTime(args[1], f.decoder.littleEndian)
		if err != nil {
			return nil, err
		}
		if !fields.valid() {
			return "Invalid", nil
		}
		return strftime(display(args[0]), fields.moment(time.UTC)), nil
	})
	defineBuiltin("std::time::format_dos_date", variadic, "$std_time_format_dos_date", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		date, err := toInt(patternInteger(args[0]))
		if err != nil {
			return nil, err
		}
		return format(optionalFormat(args, "{:04}-{:02}-{:02}"), []runtimeValue{1980 + date>>9, date >> 5 & 0xf, date & 0x1f}), nil
	})
	defineBuiltin("std::time::format_dos_time", variadic, "$std_time_format_dos_time", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		dosTime, err := toInt(patternInteger(args[0]))
		if err != nil {
			return nil, err
		}
		return format(optionalFormat(args, "{:02}:{:02}:{:02}"), []runtimeValue{dosTime >> 11, dosTime >> 5 & 0x3f, (dosTime & 0x1f) * 2}), nil
	})
	defineBuiltin("std::time::to_dos_date", 1, "$std_time_to_dos_date", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		date, err := toInt(patternInteger(args[0]))
		if err != nil {
			return nil, err
		}
		return recordValue("std::time::DOSDate", []string{"day", "month", "year"}, []int64{date & 0x1f, date >> 5 & 0xf, date >> 9}), nil
	})
	defineBuiltin("std::time::to_dos_time", 1, "$std_time_to_dos_time", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		dosTime, err := toInt(patternInteger(args[0]))
		if err != nil {
			return nil, err
		}
		return recordValue("std::time::DOSTime", []string{"seconds", "minutes", "hours"}, []int64{dosTime & 0x1f, dosTime >> 5 & 0x3f, dosTime >> 11}), nil
	})
	defineBuiltin("std::time::filetime_to_unix", 1, "$std_time_filetime_to_unix", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		filetime, err := toInt(args[0])
		if err != nil {
			return nil, err
		}
		return filetime/10000000 - 11644473600, nil
	})
}

func optionalFormat(args []runtimeValue, fallback string) string {
	if len(args) > 1 {
		return display(args[1])
	}
	return fallback
}

func patternInteger(v runtimeValue) runtimeValue {
	if node, isPattern := v.(*DecodedValue); isPattern {
		return node.raw
	}
	return v
}

func recordValue(typeName string, names []string, numbers []int64) *DecodedValue {
	node := &DecodedValue{Type: typeName}
	node.raw = node
	for i, name := range names {
		node.Fields = append(node.Fields, &DecodedValue{Name: name, Type: "u16", Value: numbers[i], ValueKind: "uint", raw: numbers[i]})
	}
	return node
}

type packedTime struct {
	second, minute, hour, monthDay, month, year, weekDay, yearDay, daylightSaving int
}

func packTime(moment time.Time, littleEndian bool) *big.Int {
	year, yearDay := uint16(moment.Year()-1900), uint16(moment.YearDay()-1)
	if !littleEndian {
		year, yearDay = bits.ReverseBytes16(year), bits.ReverseBytes16(yearDay)
	}
	bytes := []byte{byte(moment.Second()), byte(moment.Minute()), byte(moment.Hour()), byte(moment.Day()), byte(moment.Month() - 1),
		byte(year), byte(year >> 8), byte(moment.Weekday()), byte(yearDay), byte(yearDay >> 8), 0, 0, 0, 0, 0, 0}
	if littleEndian {
		slices.Reverse(bytes)
	}
	return new(big.Int).SetBytes(bytes)
}

func unpackTime(v runtimeValue, littleEndian bool) (packedTime, error) {
	packed, err := toBig(v)
	if err != nil {
		return packedTime{}, err
	}
	bytes := make([]byte, 16)
	new(big.Int).And(packed, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))).FillBytes(bytes)
	if littleEndian {
		slices.Reverse(bytes)
	}
	year, yearDay := uint16(bytes[5])|uint16(bytes[6])<<8, uint16(bytes[8])|uint16(bytes[9])<<8
	if !littleEndian {
		year, yearDay = bits.ReverseBytes16(year), bits.ReverseBytes16(yearDay)
	}
	return packedTime{second: int(bytes[0]), minute: int(bytes[1]), hour: int(bytes[2]), monthDay: int(bytes[3]), month: int(bytes[4]),
		year: int(int16(year)), weekDay: int(bytes[7]), yearDay: int(yearDay), daylightSaving: int(int8(bytes[10]))}, nil
}

func (t packedTime) valid() bool {
	return t.second <= 61 && t.minute <= 59 && t.hour <= 23 && t.monthDay >= 1 && t.monthDay <= 31 && t.month <= 11 &&
		t.weekDay <= 6 && t.yearDay <= 365 && t.daylightSaving >= -1 && t.daylightSaving <= 1
}

func (t packedTime) moment(location *time.Location) time.Time {
	return time.Date(1900+t.year, time.Month(t.month+1), t.monthDay, t.hour, t.minute, t.second, 0, location)
}

func strftime(layout string, moment time.Time) string {
	var out strings.Builder
	for i := 0; i < len(layout); i++ {
		if layout[i] != '%' || i+1 >= len(layout) {
			out.WriteByte(layout[i])
			continue
		}
		i++
		switch layout[i] {
		case 'Y':
			fmt.Fprintf(&out, "%04d", moment.Year())
		case 'y':
			fmt.Fprintf(&out, "%02d", moment.Year()%100)
		case 'm':
			fmt.Fprintf(&out, "%02d", int(moment.Month()))
		case 'd':
			fmt.Fprintf(&out, "%02d", moment.Day())
		case 'H':
			fmt.Fprintf(&out, "%02d", moment.Hour())
		case 'M':
			fmt.Fprintf(&out, "%02d", moment.Minute())
		case 'S':
			fmt.Fprintf(&out, "%02d", moment.Second())
		case 'j':
			fmt.Fprintf(&out, "%03d", moment.YearDay())
		case 'a':
			out.WriteString(moment.Weekday().String()[:3])
		case 'A':
			out.WriteString(moment.Weekday().String())
		case 'b':
			out.WriteString(moment.Month().String()[:3])
		case 'B':
			out.WriteString(moment.Month().String())
		case 'F':
			fmt.Fprintf(&out, "%04d-%02d-%02d", moment.Year(), int(moment.Month()), moment.Day())
		case 'T', 'X':
			fmt.Fprintf(&out, "%02d:%02d:%02d", moment.Hour(), moment.Minute(), moment.Second())
		case 'c':
			fmt.Fprintf(&out, "%s %s %2d %02d:%02d:%02d %04d", moment.Weekday().String()[:3], moment.Month().String()[:3], moment.Day(),
				moment.Hour(), moment.Minute(), moment.Second(), moment.Year())
		case 'e':
			fmt.Fprintf(&out, "%2d", moment.Day())
		case 'D', 'x':
			fmt.Fprintf(&out, "%02d/%02d/%02d", int(moment.Month()), moment.Day(), moment.Year()%100)
		case 'R':
			fmt.Fprintf(&out, "%02d:%02d", moment.Hour(), moment.Minute())
		case 'I':
			fmt.Fprintf(&out, "%02d", (moment.Hour()+11)%12+1)
		case 'p':
			out.WriteString(map[bool]string{false: "AM", true: "PM"}[moment.Hour() >= 12])
		case '%':
			out.WriteByte('%')
		default:
			out.WriteByte('%')
			out.WriteByte(layout[i])
		}
	}
	return out.String()
}

func defineLimitBuiltins() {
	limits := map[string]runtimeValue{
		"u8_min": uint64(0), "u8_max": uint64(math.MaxUint8),
		"u16_min": uint64(0), "u16_max": uint64(math.MaxUint16),
		"u32_min": uint64(0), "u32_max": uint64(math.MaxUint32),
		"u64_min": uint64(0), "u64_max": uint64(math.MaxUint64),
		"u128_min": uint64(0), "u128_max": uint64(math.MaxUint64),
		"s8_min": int64(math.MinInt8), "s8_max": int64(math.MaxInt8),
		"s16_min": int64(math.MinInt16), "s16_max": int64(math.MaxInt16),
		"s32_min": int64(math.MinInt32), "s32_max": int64(math.MaxInt32),
		"s64_min": int64(math.MinInt64), "s64_max": int64(math.MaxInt64),
		"s128_min": int64(math.MinInt64), "s128_max": int64(math.MaxInt64),
	}
	for name, limit := range limits {
		defineBuiltin("std::limits::"+name, 0, "$std_limits_"+name, func(f *frame, args []runtimeValue) (runtimeValue, error) {
			return limit, nil
		})
	}
}

func defineHashBuiltins() {
	defineBuiltin("std::hash::crc32", 6, "$std_hash_crc32", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		return f.crc(args, 32)
	})
	defineBuiltin("std::hash::crc16", 6, "$std_hash_crc16", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		return f.crc(args, 16)
	})
	defineBuiltin("std::hash::crc8", 6, "$std_hash_crc8", func(f *frame, args []runtimeValue) (runtimeValue, error) {
		return f.crc(args, 8)
	})
}

func (f *frame) crc(args []runtimeValue, width uint) (runtimeValue, error) {
	node, isPattern := args[0].(*DecodedValue)
	if !isPattern || node.Size == nil {
		return nil, fmt.Errorf("crc expects a pattern")
	}
	bytes, available := f.decoder.bytes(node.Offset, *node.Size)
	if !available {
		return nil, errTruncated
	}
	numbers := make([]uint64, 5)
	for i := range numbers {
		number, err := toInt(args[i+1])
		if err != nil {
			return nil, err
		}
		numbers[i] = uint64(number)
	}
	return crc(bytes, width, numbers[0], numbers[1], numbers[2], numbers[3] != 0, numbers[4] != 0), nil
}

func crc(data []byte, width uint, initial uint64, polynomial uint64, xorOut uint64, reflectIn bool, reflectOut bool) uint64 {
	mask := uint64(1)<<width - 1
	if width == 64 {
		mask = math.MaxUint64
	}
	top := uint64(1) << (width - 1)
	remainder := initial & mask
	for _, b := range data {
		if reflectIn {
			b = reflectByte(b)
		}
		remainder ^= uint64(b) << (width - 8)
		for bit := 0; bit != 8; bit++ {
			if remainder&top != 0 {
				remainder = (remainder << 1) ^ polynomial
			} else {
				remainder <<= 1
			}
			remainder &= mask
		}
	}
	if reflectOut {
		remainder = reflectBits(remainder, width)
	}
	return (remainder ^ xorOut) & mask
}

func reflectByte(b byte) byte {
	return byte(reflectBits(uint64(b), 8))
}

func reflectBits(value uint64, width uint) uint64 {
	var reflected uint64
	for i := uint(0); i != width; i++ {
		if value&(1<<i) != 0 {
			reflected |= 1 << (width - 1 - i)
		}
	}
	return reflected
}
