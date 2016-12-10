#!/usr/bin/env python

import os
import re
import sys

class ApiEnum:
    def __init__(self, name):
        self.name = name
        self.name_lc = camel_identifier_to_lc(self.name)
        self.name_uc = camel_identifier_to_uc(self.name)
        self.c_name = 'Frida' + name
        self.c_name_lc = camel_identifier_to_lc(self.c_name)
        self.c_definition = None
        self.vapi_declaration = None
        self.vapi_members = []

class ApiObjectType:
    def __init__(self, name, kind):
        self.name = name
        self.name_lc = camel_identifier_to_lc(self.name)
        self.name_uc = camel_identifier_to_uc(self.name)
        self.kind = kind
        self.property_names = []
        self.method_names = []
        self.c_name = 'Frida' + name
        self.c_name_lc = camel_identifier_to_lc(self.c_name)
        self.c_get_type = None
        self.c_constructor = None
        self.c_getter_prototypes = []
        self.c_method_prototypes = []
        self.c_delegate_typedefs = []
        self.vapi_declaration = None
        self.vapi_signals = []
        self.vapi_properties = []
        self.vapi_constructor = None
        self.vapi_methods = []

    def sort_members(self):
        self.vapi_properties = fuzzysort(self.vapi_properties, self.property_names)
        self.vapi_methods = fuzzysort(self.vapi_methods, self.method_names)

def get_contents(filename):
    with open(filename) as f:
        return f.read()

def camel_identifier_to_lc(camel_identifier):
    result = ""
    for c in camel_identifier:
        if c.istitle() and len(result) > 0:
            result += '_'
        result += c.lower()
    return result

def camel_identifier_to_uc(camel_identifier):
    result = ""
    for c in camel_identifier:
        if c.istitle() and len(result) > 0:
            result += '_'
        result += c.upper()
    return result

def beautify_cenum(cenum):
    return cenum.replace("  ", " ").replace("\t", "  ")

def beautify_cprototype(cprototype):
    result = re.sub(r"([a-z0-9])\*", r"\1 *", cprototype)
    result = re.sub(r"\(\*", r"(* ", result)
    result = re.sub(r"(, )void \* (.+?)_target\b", r"\1gpointer \2_data", result)
    result = result.replace("void * user_data", "gpointer user_data")
    result = result.replace("_length1", "_length")
    result = result.replace(" _callback_,", " callback,")
    result = result.replace(" _user_data_", " user_data")
    result = result.replace(" _res_", " result")
    return result

def fuzzysort(items, keys):
    result = []
    remaining = list(items)
    for key in keys:
        for item in remaining:
            if (" " + key + " ") in item:
                remaining.remove(item)
                result.append(item)
                break
    result.extend(remaining)
    return result

if __name__ == '__main__':
    api_vala_filename = sys.argv[1]
    core_vapi_filename = sys.argv[2]
    core_header_filename = sys.argv[3]
    interfaces_vapi_filename = sys.argv[4]
    interfaces_header_filename = sys.argv[5]
    output_dir = sys.argv[6]

    api_vala = get_contents(api_vala_filename)
    core_header = get_contents(core_header_filename)
    interfaces_vapi = get_contents(interfaces_vapi_filename)
    interfaces_header = get_contents(interfaces_header_filename)

    api_enums = [ApiEnum(m.group(1)) for m in re.finditer(r"^\t+public\s+enum\s+(\w+)\s+", api_vala, re.MULTILINE)]
    enum_by_name = {}
    for enum in api_enums:
        enum_by_name[enum.name] = enum
    for enum in api_enums:
        for m in re.finditer(r"typedef\s+enum\s+.*?\s+(\w+);", core_header, re.DOTALL):
            if m.group(1) == enum.c_name:
                enum.c_definition = beautify_cenum(m.group(0))
                break

    errors = [ApiEnum(m.group(1)) for m in re.finditer(r"^\t+public\s+errordomain\s+(\w+)\s+", interfaces_vapi, re.MULTILINE)]
    for enum in errors:
        for m in re.finditer(r"typedef\s+enum\s+.*?\s+(\w+);", interfaces_header, re.DOTALL):
            if m.group(1) == enum.c_name:
                enum.c_definition = beautify_cenum(m.group(0))
                break

    api_object_types = [ApiObjectType(m.group(2), m.group(1)) for m in re.finditer(r"^\t+public\s+(class|interface)\s+(\w+)\s+", api_vala, re.MULTILINE)]
    object_type_by_name = {}
    for klass in api_object_types:
        object_type_by_name[klass.name] = klass
    seen_cfunctions = set()
    seen_cdelegates = set()
    for object_type in sorted(api_object_types, key=lambda klass: len(klass.c_name_lc), reverse=True):
        for m in re.finditer(r"^.*?\s+" + object_type.c_name_lc + r"_(\w+)\s+.*;", core_header, re.MULTILINE):
            method_cprototype = beautify_cprototype(m.group(0))
            method_name = m.group(1)
            method_cname_lc = object_type.c_name_lc + '_' + method_name
            if method_cname_lc not in seen_cfunctions:
                seen_cfunctions.add(method_cname_lc)
                if method_name not in ('construct', 'get_main_context', 'get_provider', 'get_session'):
                    if (object_type.c_name + '*') in m.group(0):
                        if method_name == 'new':
                            if not object_type.name.endswith("List") and method_cprototype.endswith("(void);"):
                                object_type.c_constructor = method_cprototype
                        elif method_name.startswith('get_') and ', ' not in method_cprototype:
                            object_type.property_names.append(method_name[4:])
                            object_type.c_getter_prototypes.append(method_cprototype)
                        else:
                            object_type.method_names.append(method_name)
                            object_type.c_method_prototypes.append(method_cprototype)
                    elif method_name == 'get_type':
                        object_type.c_get_type = method_cprototype
        for d in re.finditer(r"^typedef.+?\(\*(" + object_type.c_name + r".+?)\) \(.+\);$", core_header, re.MULTILINE):
            delegate_cname = d.group(1)
            if delegate_cname not in seen_cdelegates:
                seen_cdelegates.add(delegate_cname)
                object_type.c_delegate_typedefs.append(beautify_cprototype(d.group(0)))

    with open(core_vapi_filename) as core_vapi_file:
        current_enum = None
        current_object_type = None
        ignoring = False
        for line in core_vapi_file:
            stripped_line = line.strip()
            level = 0
            for c in line:
                if c == '\t':
                    level += 1
                else:
                    break
            if level == 0:
                pass
            elif level == 1:
                if ignoring:
                    if stripped_line == "}":
                        ignoring = False
                else:
                    if stripped_line.startswith("public abstract"):
                        ignoring = True
                    elif stripped_line.startswith("public enum"):
                        name = re.match(r"^public enum (\w+) ", stripped_line).group(1)
                        if name not in enum_by_name:
                            ignoring = True
                        else:
                            current_enum = enum_by_name[name]
                            current_enum.vapi_declaration = stripped_line
                    elif stripped_line.startswith("public class") or stripped_line.startswith("public interface"):
                        name = re.match(r"^public (class|interface) (\w+) ", stripped_line).group(2)
                        if name not in object_type_by_name:
                            ignoring = True
                        else:
                            current_object_type = object_type_by_name[name]
                            current_object_type.vapi_declaration = stripped_line
                    elif stripped_line == "}":
                        current_enum = None
                        current_object_type = None
            elif current_enum is not None:
                current_enum.vapi_members.append(stripped_line)
            elif current_object_type is not None and stripped_line.startswith("public"):
                if stripped_line.startswith("public " + current_object_type.name + " (") or stripped_line.startswith("public static Frida." + current_object_type.name + " @new ("):
                    if current_object_type.c_constructor is not None:
                        current_object_type.vapi_constructor = stripped_line
                elif stripped_line.startswith("public signal"):
                    current_object_type.vapi_signals.append(stripped_line)
                elif "{ get" in stripped_line:
                    name = re.match(r".+?(\w+)\s+{", stripped_line).group(1)
                    if name not in ('main_context', 'provider', 'session'):
                        current_object_type.vapi_properties.append(stripped_line)
                else:
                    name = re.match(r".+?(\w+)\s+\(", stripped_line).group(1)
                    if not name.startswith("_") and name != 'dispose':
                        current_object_type.vapi_methods.append(stripped_line)
        for object_type in api_object_types:
            object_type.sort_members()

    with open(os.path.join(output_dir, 'frida-core-1.0.deps'), 'wt') as output_deps_file:
        output_deps_file.write("glib-2.0\n")
        output_deps_file.write("gobject-2.0\n")
        output_deps_file.write("gio-2.0\n")

    with open(os.path.join(output_dir, 'frida-core-1.0.vapi'), 'wt') as output_vapi_file:
        output_vapi_file.write("[CCode (cheader_filename = \"frida-core.h\", cprefix = \"Frida\", lower_case_cprefix = \"frida_\")]")
        output_vapi_file.write("\nnamespace Frida {")
        output_vapi_file.write("\n\tpublic static void init ();")
        output_vapi_file.write("\n\tpublic static void shutdown ();")
        output_vapi_file.write("\n\tpublic static void deinit ();")
        output_vapi_file.write("\n\tpublic static unowned GLib.MainContext get_main_context ();")

        for enum in api_enums:
            output_vapi_file.write("\n\n\t%s\n\t\t" % enum.vapi_declaration)
            output_vapi_file.write("\n\t\t".join(enum.vapi_members))
            output_vapi_file.write("\n\t}")

        for object_type in api_object_types:
            output_vapi_file.write("\n\n\t%s" % object_type.vapi_declaration)
            sections = []
            if len(object_type.vapi_properties) > 0:
                sections.append("\n\t\t" + "\n\t\t".join(object_type.vapi_properties))
            if object_type.vapi_constructor is not None:
                sections.append("\n\t\t" + object_type.vapi_constructor)
            if len(object_type.vapi_methods) > 0:
                sections.append("\n\t\t" + "\n\t\t".join(object_type.vapi_methods))
            if len(object_type.vapi_signals) > 0:
                sections.append("\n\t\t" + "\n\t\t".join(object_type.vapi_signals))
            output_vapi_file.write("\n".join(sections))
            output_vapi_file.write("\n\t}")

        output_vapi_file.write("\n}\n")

    with open(os.path.join(output_dir, 'frida-core.h'), 'wt') as output_header_file:
        output_header_file.write("#ifndef __FRIDA_CORE_H__\n#define __FRIDA_CORE_H__\n\n")

        output_header_file.write("#include <glib.h>\n#include <glib-object.h>\n#include <gio/gio.h>\n#include <json-glib/json-glib.h>\n")

        output_header_file.write("\nG_BEGIN_DECLS\n")

        for object_type in api_object_types:
            output_header_file.write("\ntypedef struct _%s %s;" % (object_type.c_name, object_type.c_name))

        for enum in api_enums:
            output_header_file.write("\n\n" + enum.c_definition)

        output_header_file.write("\n\n/* Library lifetime */")
        output_header_file.write("\nvoid frida_init (void);")
        output_header_file.write("\nvoid frida_shutdown (void);")
        output_header_file.write("\nvoid frida_deinit (void);")
        output_header_file.write("\nGMainContext * frida_get_main_context (void);")

        output_header_file.write("\n\n/* Object lifetime */")
        output_header_file.write("\nvoid frida_unref (gpointer obj);")

        output_header_file.write("\n\n/* Library versioning */")
        output_header_file.write("\nvoid frida_version (guint * major, guint * minor, guint * micro, guint * nano);")
        output_header_file.write("\nconst gchar * frida_version_string (void);")

        for object_type in api_object_types:
            output_header_file.write("\n\n/* %s */" % object_type.name)
            sections = []
            if len(object_type.c_delegate_typedefs) > 0:
                sections.append("\n" + "\n".join(object_type.c_delegate_typedefs))
            if object_type.c_constructor is not None:
                sections.append("\n" + object_type.c_constructor)
            if len(object_type.c_getter_prototypes) > 0:
                sections.append("\n" + "\n".join(object_type.c_getter_prototypes))
            if len(object_type.c_method_prototypes) > 0:
                sections.append("\n" + "\n".join(object_type.c_method_prototypes))
            output_header_file.write("\n".join(sections))

        if len(errors) > 0:
            output_header_file.write("\n\n/* Errors */\n")
            output_header_file.write("\n\n".join(map(lambda enum: "GQuark frida_%(name_lc)s_quark (void);\n" \
                % { 'name_lc': enum.name_lc }, errors)))
            output_header_file.write("\n")
            output_header_file.write("\n\n".join(map(lambda enum: enum.c_definition, errors)))

        output_header_file.write("\n\n/* GTypes */")
        for enum in api_enums:
            output_header_file.write("\nGType %s_get_type (void) G_GNUC_CONST;" % enum.c_name_lc)
        for object_type in api_object_types:
            if object_type.c_get_type is not None:
                output_header_file.write("\n" + object_type.c_get_type)

        output_header_file.write("\n\n/* Macros */")
        macros = []
        for enum in api_enums:
            macros.append("#define FRIDA_TYPE_%(name_uc)s (frida_%(name_lc)s_get_type ())" \
                % { 'name_lc': enum.name_lc, 'name_uc': enum.name_uc })
        for object_type in api_object_types:
            macros.append("""#define FRIDA_TYPE_%(name_uc)s (frida_%(name_lc)s_get_type ())
#define FRIDA_%(name_uc)s(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), FRIDA_TYPE_%(name_uc)s, Frida%(name)s))
#define FRIDA_IS_%(name_uc)s(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), FRIDA_TYPE_%(name_uc)s))""" \
                % { 'name': object_type.name, 'name_lc': object_type.name_lc, 'name_uc': object_type.name_uc })

        for enum in errors:
            macros.append("#define FRIDA_%(name_uc)s (frida_%(name_lc)s_quark ())" \
                % { 'name_lc': enum.name_lc, 'name_uc': enum.name_uc })
        output_header_file.write("\n" + "\n\n".join(macros))

        output_header_file.write("\n\nG_END_DECLS")

        output_header_file.write("\n\n#endif\n")
