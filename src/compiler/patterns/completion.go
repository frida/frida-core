package patterns

import (
	"sort"
	"strings"
	"sync"
	"unicode/utf16"
)

func (s *LanguageService) Completions(uri string, position TextPosition) []CompletionItem {
	d := s.documents[uri]
	if d == nil {
		return []CompletionItem{}
	}
	return d.completions(locateCompletion(d.textBefore(position)))
}

func (d *serviceDocument) textBefore(position TextPosition) string {
	if position.Line >= len(d.lines) {
		return d.text
	}
	units := utf16.Encode([]rune(d.lineText(position.Line)))
	column := string(utf16.Decode(units[:min(position.Character, len(units))]))
	return d.text[:d.lines[position.Line]] + column
}

func (d *serviceDocument) completions(request completionRequest) []CompletionItem {
	list := &completionList{seen: map[string]bool{}, items: []CompletionItem{}}
	switch request.site {
	case siteFileStatement:
		list.offerKeywords(fileKeywords)
		d.offerTypes(list)
		d.offerFunctions(list)
	case siteMemberStatement:
		list.offerKeywords(memberKeywords)
		d.offerTypes(list)
		if request.qualifier != "" {
			d.offerFunctions(list)
		}
	case siteBitfieldStatement:
		list.offerKeywords(bitfieldKeywords)
		d.offerTypes(list)
		if request.qualifier != "" {
			d.offerFunctions(list)
		}
	case siteFunctionStatement:
		list.offerKeywords(functionKeywords)
		list.offerLocals(request.locals)
		d.offerTypes(list)
		d.offerFunctions(list)
	case siteType:
		d.offerTypes(list)
	case siteBaseType:
		d.offerCompositeTypes(list)
	case siteIntegerType:
		list.offerIntegerTypes()
	case siteParameter:
		list.offerKeywords(parameterKeywords)
		d.offerTypes(list)
	case siteValue, siteArraySize:
		list.offerLocals(request.locals)
		if request.site == siteArraySize {
			list.offerKeywords([]string{"while"})
		}
		list.offerKeywords(valueKeywords)
		d.offerEnumMembers(list)
		d.offerFunctions(list)
	case siteAttribute:
		list.offerNames(attributeNames, completionProperty, "attribute")
	case siteFunctionReference:
		d.offerFunctions(list)
	case siteVisualizer:
		list.offerNames(detachedVisualizers, completionValue, "visualizer")
	case siteInlineVisualizer:
		list.offerNames(inlineVisualizers, completionValue, "inline visualizer")
	}
	return list.relativeTo(request.qualifier)
}

func (d *serviceDocument) offerTypes(list *completionList) {
	d.offerCompositeTypes(list)
	for _, decl := range d.visibleDeclarations() {
		switch decl.(type) {
		case *EnumDecl:
			list.offer(decl.declaredName(), completionEnum, "enum")
		case *UsingDecl:
			list.offer(decl.declaredName(), completionClass, "using")
		}
	}
	for _, name := range primitiveTypeNames {
		if name != "padding" {
			list.offer(name, completionClass, "builtin type")
		}
	}
}

func (d *serviceDocument) offerFunctions(list *completionList) {
	for _, decl := range d.visibleDeclarations() {
		if _, isFunction := decl.(*FunctionDecl); isFunction {
			list.offer(decl.declaredName(), completionFunction, "fn")
		}
	}
	names := make([]string, 0, len(builtins))
	for name := range builtins {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		list.offer(name, completionFunction, "builtin")
	}
}

func (d *serviceDocument) offerCompositeTypes(list *completionList) {
	for _, decl := range d.visibleDeclarations() {
		switch decl.(type) {
		case *StructDecl, *UnionDecl, *BitfieldDecl:
			list.offer(decl.declaredName(), completionStruct, describeDeclaration(decl))
		}
	}
}

func (d *serviceDocument) offerEnumMembers(list *completionList) {
	for _, decl := range d.visibleDeclarations() {
		if enum, isEnum := decl.(*EnumDecl); isEnum {
			for _, member := range enum.Members {
				list.offer(enum.declaredName()+"::"+member.Name, completionEnumMember, enum.declaredName())
			}
		}
	}
}

func (d *serviceDocument) visibleDeclarations() []Declaration {
	if !d.importsStandardLibrary() {
		return d.file.Declarations
	}
	return append(standardLibraryDeclarations(), d.file.Declarations...)
}

func (d *serviceDocument) importsStandardLibrary() bool {
	for _, include := range d.file.Includes {
		if strings.HasPrefix(include.Path, "std/") {
			return true
		}
	}
	for _, imported := range d.file.Imports {
		if strings.HasPrefix(imported.Path, "std/") {
			return true
		}
	}
	return false
}

var standardLibraryDeclarations = sync.OnceValue(func() []Declaration {
	file, _ := ParseFile(standardLibraryPath, standardLibrarySource)
	return file.Declarations
})

type completionList struct {
	seen  map[string]bool
	items []CompletionItem
}

func (l *completionList) offerKeywords(keywords []string) {
	l.offerNames(keywords, completionKeyword, "keyword")
}

func (l *completionList) offerLocals(names []string) {
	l.offerNames(names, completionVariable, "local")
}

func (l *completionList) offerIntegerTypes() {
	for _, name := range primitiveTypeNames {
		if isIntegerTypeName(name) {
			l.offer(name, completionClass, "builtin type")
		}
	}
}

func (l *completionList) offerNames(names []string, kind int, detail string) {
	for _, name := range names {
		l.offer(name, kind, detail)
	}
}

func (l *completionList) relativeTo(qualifier string) []CompletionItem {
	if qualifier == "" {
		return l.items
	}
	items := []CompletionItem{}
	for _, item := range l.items {
		if strings.HasPrefix(item.Label, qualifier) {
			item.Label = strings.TrimPrefix(item.Label, qualifier)
			items = append(items, item)
		}
	}
	return items
}

func (l *completionList) offer(label string, kind int, detail string) {
	if l.seen[label] {
		return
	}
	l.seen[label] = true
	l.items = append(l.items, CompletionItem{Label: label, Kind: kind, Detail: detail})
}

func isIntegerTypeName(name string) bool {
	return (name[0] == 'u' || name[0] == 's') && name[1] >= '0' && name[1] <= '9'
}

var fileKeywords = []string{"struct", "union", "enum", "bitfield", "fn", "namespace", "using", "import", "if", "else", "match", "be", "le"}

var memberKeywords = []string{"padding", "if", "else", "match", "try", "catch", "break", "continue", "be", "le", "const"}

var bitfieldKeywords = []string{"padding", "if", "else", "match", "be", "le"}

var functionKeywords = []string{"if", "else", "while", "for", "match", "return", "break", "continue", "try", "catch", "const"}

var parameterKeywords = []string{"ref", "in", "out", "auto", "const"}

var valueKeywords = []string{"this", "parent", "true", "false", "null", "sizeof", "addressof", "typenameof"}

var attributeNames = []string{
	"name", "comment", "color", "format", "format_read", "format_entries", "format_read_entries", "transform",
	"transform_entries", "pointer_base", "fixed_size", "inline", "sealed", "hidden", "highlight_hidden", "tree_hidden",
	"no_unique_address", "export", "bitfield_order", "hex::visualize", "hex::inline_visualize",
}

var detachedVisualizers = []string{
	"line_plot", "scatter_plot", "image", "bitmap", "3d", "sound", "coordinates", "timestamp", "table", "digital_signal",
	"hex_viewer", "chunk_entropy", "disassembler",
}

var inlineVisualizers = []string{"color", "gauge", "button"}
