#!/usr/bin/env python3

import argparse
import os
import re
import sys


def main():
    parser = argparse.ArgumentParser(description="Generate refined Frida API definitions")
    parser.add_argument('--output', dest='output_type', choices=['bundle', 'header', 'vapi'], default='bundle')
    parser.add_argument('api_version', metavar='api-version', type=str)
    parser.add_argument('api_vala', metavar='/path/to/frida.vala', type=argparse.FileType('r', encoding='utf-8'))
    parser.add_argument('core_vapi', metavar='/path/to/frida-core.vapi', type=argparse.FileType('r', encoding='utf-8'))
    parser.add_argument('core_header', metavar='/path/to/frida-core.h', type=argparse.FileType('r', encoding='utf-8'))
    parser.add_argument('interfaces_vapi', metavar='/path/to/frida-interfaces.vapi', type=argparse.FileType('r', encoding='utf-8'))
    parser.add_argument('interfaces_header', metavar='/path/to/frida-interfaces.h', type=argparse.FileType('r', encoding='utf-8'))
    parser.add_argument('output_dir', metavar='/output/dir')

    args = parser.parse_args()

    api_version = args.api_version
    api_vala = args.api_vala.read()
    core_vapi = args.core_vapi.read()
    core_header = args.core_header.read()
    interfaces_vapi = args.interfaces_vapi.read()
    interfaces_header = args.interfaces_header.read()
    output_dir = args.output_dir

    enable_header = False
    enable_vapi = False
    output_type = args.output_type
    if output_type == 'bundle':
        enable_header = True
        enable_vapi = True
    elif output_type == 'header':
        enable_header = True
    elif output_type == 'vapi':
        enable_vapi = True

    api = parse_api(api_version, api_vala, core_vapi, core_header, interfaces_vapi, interfaces_header)

    if enable_header:
        emit_header(api, output_dir)

    if enable_vapi:
        emit_vapi(api, output_dir)

def emit_header(api, output_dir):
    with open(os.path.join(output_dir, 'frida-core.h'), 'wt') as output_header_file:
        output_header_file.write("#ifndef __FRIDA_CORE_H__\n#define __FRIDA_CORE_H__\n\n")

        output_header_file.write("#include <glib.h>\n#include <glib-object.h>\n#include <gio/gio.h>\n#include <json-glib/json-glib.h>\n")

        output_header_file.write("\nG_BEGIN_DECLS\n")

        for object_type in api.object_types:
            output_header_file.write("\ntypedef struct _%s %s;" % (object_type.c_name, object_type.c_name))

        for enum in api.enum_types:
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

        for object_type in api.object_types:
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

        if len(api.error_types) > 0:
            output_header_file.write("\n\n/* Errors */\n")
            output_header_file.write("\n\n".join(map(lambda enum: "GQuark frida_%(name_lc)s_quark (void);\n" \
                % { 'name_lc': enum.name_lc }, api.error_types)))
            output_header_file.write("\n")
            output_header_file.write("\n\n".join(map(lambda enum: enum.c_definition, api.error_types)))

        output_header_file.write("\n\n/* GTypes */")
        for enum in api.enum_types:
            output_header_file.write("\nGType %s_get_type (void) G_GNUC_CONST;" % enum.c_name_lc)
        for object_type in api.object_types:
            if object_type.c_get_type is not None:
                output_header_file.write("\n" + object_type.c_get_type)

        output_header_file.write("\n\n/* Macros */")
        macros = []
        for enum in api.enum_types:
            macros.append("#define FRIDA_TYPE_%(name_uc)s (frida_%(name_lc)s_get_type ())" \
                % { 'name_lc': enum.name_lc, 'name_uc': enum.name_uc })
        for object_type in api.object_types:
            macros.append("""#define FRIDA_TYPE_%(name_uc)s (frida_%(name_lc)s_get_type ())
#define FRIDA_%(name_uc)s(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), FRIDA_TYPE_%(name_uc)s, Frida%(name)s))
#define FRIDA_IS_%(name_uc)s(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), FRIDA_TYPE_%(name_uc)s))""" \
                % { 'name': object_type.name, 'name_lc': object_type.name_lc, 'name_uc': object_type.name_uc })

        for enum in api.error_types:
            macros.append("#define FRIDA_%(name_uc)s (frida_%(name_lc)s_quark ())" \
                % { 'name_lc': enum.name_lc, 'name_uc': enum.name_uc })
        output_header_file.write("\n" + "\n\n".join(macros))

        output_header_file.write("\n\nG_END_DECLS")

        output_header_file.write("\n\n#endif\n")

def emit_vapi(api, output_dir):
    with open(os.path.join(output_dir, "frida-core-{0}.vapi".format(api.version)), "wt") as output_vapi_file:
        output_vapi_file.write("[CCode (cheader_filename = \"frida-core.h\", cprefix = \"Frida\", lower_case_cprefix = \"frida_\")]")
        output_vapi_file.write("\nnamespace Frida {")
        output_vapi_file.write("\n\tpublic static void init ();")
        output_vapi_file.write("\n\tpublic static void shutdown ();")
        output_vapi_file.write("\n\tpublic static void deinit ();")
        output_vapi_file.write("\n\tpublic static unowned GLib.MainContext get_main_context ();")

        for object_type in api.object_types:
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

        for enum in api.error_types:
            output_vapi_file.write("\n\n\t%s\n\t\t" % enum.vapi_declaration)
            output_vapi_file.write("\n\t\t".join(enum.vapi_members))
            output_vapi_file.write("\n\t}")

        for enum in api.enum_types:
            output_vapi_file.write("\n\n\t%s\n\t\t" % enum.vapi_declaration)
            output_vapi_file.write("\n\t\t".join(enum.vapi_members))
            output_vapi_file.write("\n\t}")

        output_vapi_file.write("\n}\n")

    with open(os.path.join(output_dir, "frida-core-{0}.deps".format(api.version)), "wt") as output_deps_file:
        output_deps_file.write("glib-2.0\n")
        output_deps_file.write("gobject-2.0\n")
        output_deps_file.write("gio-2.0\n")

def parse_api(api_version, api_vala, core_vapi, core_header, interfaces_vapi, interfaces_header):
    all_enum_names = [m.group(1) for m in re.finditer(r"^\t+public\s+enum\s+(\w+)\s+", api_vala + "\n" + interfaces_vapi, re.MULTILINE)]
    enum_types = []

    interfaces_public_types = {
        "ScriptOptions": "Script",
    }
    internal_type_prefixes = [
        "Fruity",
        "HostSession",
        "SpawnStartState",
        "MessageType",
        "ResultCode",
        "Winjector"
    ]
    seen_enum_names = set()
    for enum_name in all_enum_names:
        if enum_name in seen_enum_names:
            continue
        seen_enum_names.add(enum_name)

        is_public = True
        for prefix in internal_type_prefixes:
            if enum_name.startswith(prefix):
                is_public = False
                break

        if is_public:
            enum_types.append(ApiEnum(enum_name))

    enum_by_name = {}
    for enum in enum_types:
        enum_by_name[enum.name] = enum
    for enum in enum_types:
        for m in re.finditer(r"typedef\s+enum\s+.*?\s+(\w+);", core_header + "\n" + interfaces_header, re.DOTALL):
            if m.group(1) == enum.c_name:
                enum.c_definition = beautify_cenum(m.group(0))
                break

    error_types = [ApiEnum(m.group(1)) for m in re.finditer(r"^\t+public\s+errordomain\s+(\w+)\s+", interfaces_vapi, re.MULTILINE)]
    error_by_name = {}
    for enum in error_types:
        error_by_name[enum.name] = enum
    for enum in error_types:
        for m in re.finditer(r"typedef\s+enum\s+.*?\s+(\w+);", interfaces_header, re.DOTALL):
            if m.group(1) == enum.c_name:
                enum.c_definition = beautify_cenum(m.group(0))
                break

    object_types = parse_vala_object_types(api_vala)

    for potential_type in parse_vala_object_types(interfaces_vapi):
        insert_after = interfaces_public_types.get(potential_type.name, None)
        if insert_after is not None:
            for i, t in enumerate(object_types):
                if t.name == insert_after:
                    object_types.insert(i + 1, potential_type)

    object_type_by_name = {}
    for klass in object_types:
        object_type_by_name[klass.name] = klass
    seen_cfunctions = set()
    seen_cdelegates = set()
    for object_type in sorted(object_types, key=lambda klass: len(klass.c_name_lc), reverse=True):
        for m in re.finditer(r"^.*?\s+" + object_type.c_name_lc + r"_(\w+)\s+[^;]+;", (core_header + interfaces_header), re.MULTILINE):
            method_cprototype = beautify_cprototype(m.group(0))
            method_name = m.group(1)
            method_cname_lc = object_type.c_name_lc + '_' + method_name
            if method_cname_lc not in seen_cfunctions:
                seen_cfunctions.add(method_cname_lc)
                if method_name not in ('construct', 'get_main_context', 'get_provider', 'get_session'):
                    if (object_type.c_name + '*') in m.group(0):
                        if method_name == 'new':
                            if not object_type.name.endswith("List") and (method_cprototype.endswith("(void);") or method_cprototype.startswith("FridaFileMonitor")):
                                object_type.c_constructor = method_cprototype
                        elif method_name.startswith('get_') and not any(arg in method_cprototype for arg in ['GAsyncReadyCallback', 'GError ** error']):
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

    current_enum = None
    current_object_type = None
    ignoring = False
    for line in (core_vapi + interfaces_vapi).split("\n"):
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
                if stripped_line.startswith("public abstract") or stripped_line.startswith("public class Promise") \
                        or stripped_line.startswith("public interface Future"):
                    ignoring = True
                elif stripped_line.startswith("public enum") or stripped_line.startswith("public errordomain"):
                    name = re.match(r"^public (?:enum|errordomain) (\w+) ", stripped_line).group(1)
                    if name in enum_by_name:
                        current_enum = enum_by_name[name]
                        current_enum.vapi_declaration = stripped_line
                    elif name in error_by_name:
                        current_enum = error_by_name[name]
                        current_enum.vapi_declaration = stripped_line
                    else:
                        ignoring = True
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
    for object_type in object_types:
        object_type.sort_members()
    for enum in enum_types:
        if enum.vapi_declaration is None:
            m = re.match(r".+\s+(public\s+enum\s+" + enum.name + r"\s+{)(.+?)}", interfaces_vapi, re.MULTILINE | re.DOTALL)
            enum.vapi_declaration = m.group(1)
            enum.vapi_members.extend([line.lstrip() for line in m.group(2).strip().split("\n")])

    return ApiSpec(api_version, object_types, enum_types, error_types)

def parse_vala_object_types(source):
    return [ApiObjectType(m.group(2), m.group(1)) for m in re.finditer(r"^\t+public\s+(class|interface)\s+(\w+)\s+", source, re.MULTILINE)]

class ApiSpec:
    def __init__(self, version, object_types, enum_types, error_types):
        self.version = version
        self.object_types = object_types
        self.enum_types = enum_types
        self.error_types = error_types

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
    result = cprototype.replace("\n", "")
    result = re.sub(r"\s+", " ", result)
    result = re.sub(r"([a-z0-9])\*", r"\1 *", result)
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
    main()
