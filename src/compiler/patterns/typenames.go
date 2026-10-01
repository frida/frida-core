package patterns

import (
	"fmt"
	"strings"
)

type namePiece struct {
	text  string
	value Value
}

func (r *resolver) namePieces(t Type, ref TypeRef) []namePiece {
	if len(ref.Args) == 0 {
		if naming, isSubstituted := r.subst.lookupNaming(ref.Name); isSubstituted {
			return piecesOf(naming, func(param *Local) Value { return &LocalRef{Local: param} })
		}
	}
	return piecesOf(namingOf(t), func(param *Local) Value { return argumentFor(t, param) })
}

func piecesOf(naming []NamePart, valueOf func(param *Local) Value) []namePiece {
	pieces := make([]namePiece, len(naming))
	for i, part := range naming {
		if part.Param == nil {
			pieces[i] = namePiece{text: part.Text}
		} else {
			pieces[i] = namePiece{value: valueOf(part.Param)}
		}
	}
	return pieces
}

func namingOf(t Type) []NamePart {
	switch t := t.(type) {
	case *Struct:
		if t.Naming != nil {
			return t.Naming
		}
	case *Union:
		if t.Naming != nil {
			return t.Naming
		}
	}
	return []NamePart{{Text: DescribeType(t)}}
}

func (r *resolver) typeNameValue(pieces []namePiece) Value {
	var name Value
	for _, piece := range pieces {
		var part Value = &StringConstant{Value: piece.text}
		if piece.value != nil {
			part = &TemplateArgument{Value: piece.value}
		}
		if name == nil {
			name = part
		} else {
			name = &BinaryOp{Operator: "+", Left: name, Right: part}
		}
	}
	return name
}

func hasDynamicNaming(t Type) bool {
	switch t := Unalias(t).(type) {
	case *Struct:
		return t.Naming != nil
	case *Union:
		return t.Naming != nil
	}
	return false
}

func argumentFor(t Type, param *Local) Value {
	args := typeArgs(t)
	for i, candidate := range typeParams(t) {
		if candidate == param {
			return args[i]
		}
	}
	panic("unreachable")
}

func dynamicNaming(parts []NamePart) []NamePart {
	var merged []NamePart
	dynamic := false
	for _, part := range parts {
		dynamic = dynamic || part.Param != nil
		if last := len(merged) - 1; last >= 0 && part.Param == nil && merged[last].Param == nil {
			merged[last].Text += part.Text
			continue
		}
		merged = append(merged, part)
	}
	if !dynamic {
		return nil
	}
	return merged
}

func (f *frame) instanceName(naming []NamePart) string {
	var name strings.Builder
	for _, part := range naming {
		if part.Param == nil {
			name.WriteString(part.Text)
		} else {
			name.WriteString(templateArgumentText(f.locals[part.Param]))
		}
	}
	return name.String()
}

func templateArgumentText(v runtimeValue) string {
	switch v := v.(type) {
	case string:
		return templateStringText(v)
	case *DecodedValue:
		return v.Type + "{ }"
	}
	return display(v)
}

func templateStringText(s string) string {
	if len(s) > 32 {
		s = "..."
	}
	var text strings.Builder
	text.WriteByte('"')
	for i := 0; i < len(s); i++ {
		b := s[i]
		escape, isNamed := byteEscapes[b]
		switch {
		case b >= 0x20 && b < 0x7f:
			text.WriteByte(b)
		case isNamed:
			text.WriteString(escape)
		default:
			fmt.Fprintf(&text, "\\x%02X", b)
		}
	}
	text.WriteByte('"')
	return text.String()
}

var byteEscapes = map[byte]string{'\a': `\a`, '\b': `\b`, '\f': `\f`, '\n': `\n`, '\r': `\r`, '\t': `\t`, '\v': `\v`}
