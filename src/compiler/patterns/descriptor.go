package patterns

import (
	"encoding/json"
)

type Description struct {
	Types       []*TypeDescription      `json:"types"`
	Root        string                  `json:"root,omitempty"`
	Inputs      []*InputDescription     `json:"inputs,omitempty"`
	Diagnostics []DiagnosticDescription `json:"diagnostics"`
}

type InputDescription struct {
	Name string              `json:"name"`
	Type *TypeRefDescription `json:"type,omitempty"`
	Doc  string              `json:"doc,omitempty"`
}

func Inputs(module *Module) []*InputDescription {
	var inputs []*InputDescription
	for _, local := range moduleInputs(module) {
		input := &InputDescription{Name: local.Name}
		if local.Type != nil {
			input.Type = describeTypeRef(local.Type)
		}
		inputs = append(inputs, input)
	}
	return inputs
}

func moduleInputs(module *Module) []*Local {
	if module.Root == nil {
		return nil
	}
	var inputs []*Local
	for _, statement := range module.Root.Body {
		if local, isLocal := statement.(*Local); isLocal && local.Input {
			inputs = append(inputs, local)
		}
	}
	return inputs
}

type DiagnosticDescription struct {
	Line      int    `json:"line"`
	Character int    `json:"character"`
	Message   string `json:"message"`
}

type TypeDescription struct {
	Kind       string                       `json:"kind"`
	Name       string                       `json:"name"`
	Doc        string                       `json:"doc,omitempty"`
	File       string                       `json:"file,omitempty"`
	Line       int                          `json:"line"`
	Character  int                          `json:"character"`
	Size       *int                         `json:"size,omitempty"`
	Align      int                          `json:"align,omitempty"`
	Fields     []*FieldDescription          `json:"fields,omitempty"`
	Underlying *TypeRefDescription          `json:"underlying,omitempty"`
	Values     []*EnumMemberDescription     `json:"values,omitempty"`
	Bits       []*BitfieldMemberDescription `json:"bits,omitempty"`
	Type       *TypeRefDescription          `json:"type,omitempty"`
}

type FieldDescription struct {
	Name            string              `json:"name"`
	Doc             string              `json:"doc,omitempty"`
	Hidden          bool                `json:"hidden,omitempty"`
	Conditional     bool                `json:"conditional,omitempty"`
	NoUniqueAddress bool                `json:"no_unique_address,omitempty"`
	Type            *TypeRefDescription `json:"type"`
	Offset          *int                `json:"offset"`
	Size            *int                `json:"size"`
}

type EnumMemberDescription struct {
	Name     string `json:"name"`
	Doc      string `json:"doc,omitempty"`
	Value    int64  `json:"value"`
	Last     int64  `json:"last"`
	Wide     string `json:"wide,omitempty"`
	WideLast string `json:"wide_last,omitempty"`
}

type BitfieldMemberDescription struct {
	Name   string `json:"name"`
	Doc    string `json:"doc,omitempty"`
	Offset int    `json:"offset"`
	Bits   int    `json:"bits"`
	Signed bool   `json:"signed,omitempty"`
	Bool   bool   `json:"bool,omitempty"`
	Enum   string `json:"enum,omitempty"`
}

type TypeRefDescription struct {
	Kind    string              `json:"kind"`
	Display string              `json:"display"`
	Name    string              `json:"name,omitempty"`
	Order   string              `json:"order,omitempty"`
	Target  *TypeRefDescription `json:"target,omitempty"`
	Width   *TypeRefDescription `json:"width,omitempty"`
	Element *TypeRefDescription `json:"element,omitempty"`
	Length  *int64              `json:"length,omitempty"`
	Sized   bool                `json:"sized,omitempty"`
	Size    int                 `json:"size,omitempty"`
}

func DescribeSource(source string, target Target) string {
	module, diagnostics := Compile(source)
	description := &Description{Diagnostics: []DiagnosticDescription{}}
	for _, d := range diagnostics {
		description.Diagnostics = append(description.Diagnostics, DiagnosticDescription{Line: d.Position.Line, Character: d.Position.Character, Message: d.Message})
	}
	if module != nil {
		description.Types = Describe(module, target)
		if module.Root != nil {
			description.Root = module.Root.Name
		}
		description.Inputs = Inputs(module)
	} else {
		description.Types = []*TypeDescription{}
	}
	encoded, _ := json.Marshal(description)
	return string(encoded)
}

func Describe(module *Module, target Target) []*TypeDescription {
	layout := module.Layout(target)
	types := []*TypeDescription{}
	for _, t := range module.Types {
		types = append(types, describeType(t, layout))
	}
	return types
}

func describeType(t NamedType, layout *ModuleLayout) *TypeDescription {
	d := describeTypeShape(t, layout)
	position := typePosition(t)
	d.File, d.Line, d.Character = position.Path, position.Line, position.Character
	return d
}

func describeTypeShape(t NamedType, layout *ModuleLayout) *TypeDescription {
	switch t := t.(type) {
	case *Struct:
		return describeComposite("struct", t.Name, t.Doc, t, layout)
	case *Union:
		return describeComposite("union", t.Name, t.Doc, t, layout)
	case *Enum:
		d := &TypeDescription{Kind: "enum", Name: t.Name, Doc: t.Doc, Underlying: describeTypeRef(enumStorage(t)), Values: []*EnumMemberDescription{}}
		d.Size, d.Align = sizeAndAlign(layout.Of(t))
		for _, member := range t.Members {
			description := &EnumMemberDescription{Name: member.Name, Doc: member.Doc, Value: member.Value, Last: member.Last}
			if member.Wide != nil {
				description.Wide = member.Wide.String()
			}
			if member.WideLast != nil {
				description.WideLast = member.WideLast.String()
			}
			d.Values = append(d.Values, description)
		}
		return d
	case *Bitfield:
		d := &TypeDescription{Kind: "bitfield", Name: t.Name, Doc: t.Doc, Bits: []*BitfieldMemberDescription{}}
		d.Size, d.Align = sizeAndAlign(layout.Of(t))
		members := t.Members
		if !t.Simple {
			for _, statement := range flattenBitfield(t.Body) {
				if member, isBit := statement.(*BitfieldMember); isBit {
					members = append(members, member)
				}
			}
		}
		for _, member := range members {
			if member.Name == "" {
				continue
			}
			bit := &BitfieldMemberDescription{Name: member.Name, Doc: member.Doc, Offset: member.Offset, Bits: member.Bits, Signed: member.Signed, Bool: member.Bool}
			if member.Enum != nil {
				bit.Enum = member.Enum.Name
			}
			d.Bits = append(d.Bits, bit)
		}
		return d
	case *Alias:
		d := &TypeDescription{Kind: "alias", Name: t.Name, Doc: t.Doc, Type: describeTypeRef(t.Target)}
		d.Size, d.Align = sizeAndAlign(layout.Of(t))
		return d
	}
	panic("unreachable")
}

func enumStorage(t *Enum) Type {
	if t.Encoding != nil {
		return t.Encoding
	}
	return t.Underlying
}

func describeComposite(kind string, name string, doc string, t Type, layout *ModuleLayout) *TypeDescription {
	d := &TypeDescription{Kind: kind, Name: name, Doc: doc, Fields: []*FieldDescription{}}
	d.Size, d.Align = sizeAndAlign(layout.Of(t))
	composite := layout.Composite(t)
	if composite == nil {
		for _, field := range compositeFields(t) {
			d.Fields = append(d.Fields, &FieldDescription{
				Name:            field.Name,
				Doc:             field.Doc,
				Hidden:          field.Hidden,
				Conditional:     field.Guard != nil,
				NoUniqueAddress: field.NoUniqueAddress,
				Type:            describeTypeRef(field.Type),
			})
		}
		return d
	}
	for _, f := range composite.Fields {
		field := &FieldDescription{
			Name:            f.Field.Name,
			Doc:             f.Field.Doc,
			Hidden:          f.Field.Hidden,
			Conditional:     f.Field.Guard != nil,
			NoUniqueAddress: f.Field.NoUniqueAddress,
			Type:            describeTypeRef(f.Field.Type),
		}
		if !f.Dynamic {
			offset := f.Offset
			field.Offset = &offset
		}
		field.Size, _ = sizeAndAlign(f.Type)
		d.Fields = append(d.Fields, field)
	}
	return d
}

func compositeFields(t Type) []*Field {
	switch t := t.(type) {
	case *Struct:
		return allFields(t)
	case *Union:
		return t.Fields
	}
	panic("unreachable")
}

func sizeAndAlign(layout *TypeLayout) (*int, int) {
	if layout.Dynamic {
		return nil, layout.Align
	}
	size := layout.Size
	return &size, layout.Align
}

func describeTypeRef(t Type) *TypeRefDescription {
	d := &TypeRefDescription{Display: DescribeType(t)}
	switch t := t.(type) {
	case *Primitive:
		d.Kind = "primitive"
		d.Name = t.Kind.Name()
		d.Order = orderName(t.Order)
	case NamedType:
		d.Kind = "named"
		d.Name = t.TypeName()
	case *Padding:
		d.Kind = "padding"
		if size, isConstant := t.Size.(*Constant); isConstant {
			d.Size = int(size.Value)
		}
	case *Pointer:
		d.Kind = "pointer"
		d.Target = describeTypeRef(t.Target)
		if t.Width != nil {
			d.Width = describeTypeRef(t.Width)
		}
	case *Array:
		d.Kind = "array"
		d.Element = describeTypeRef(t.Element)
		d.Sized = t.Length != nil
		if length, isConstant := t.Length.(*Constant); isConstant {
			value := length.Value
			d.Length = &value
		}
	}
	return d
}

func orderName(order ByteOrder) string {
	switch order {
	case LittleEndian:
		return "little"
	case BigEndian:
		return "big"
	}
	return "native"
}
