#!/usr/bin/env python3

import argparse
import os
from pathlib import Path
import re
import sys


def main():
    parser = argparse.ArgumentParser(description="Generate refined Frida API definitions")
    parser.add_argument('--output', dest='output_type', choices=['bundle', 'header', 'vapi'], default='bundle')
    parser.add_argument('api_version', metavar='api-version', type=str)
    parser.add_argument('core_vapi', metavar='/path/to/frida-core.vapi', type=argparse.FileType('r', encoding='utf-8'))
    parser.add_argument('core_header', metavar='/path/to/frida-core.h', type=argparse.FileType('r', encoding='utf-8'))
    parser.add_argument('base_vapi', metavar='/path/to/frida-base.vapi', type=argparse.FileType('r', encoding='utf-8'))
    parser.add_argument('base_header', metavar='/path/to/frida-base.h', type=argparse.FileType('r', encoding='utf-8'))
    parser.add_argument('output_dir', metavar='/output/dir')

    args = parser.parse_args()

    api_version = args.api_version
    core_vapi = args.core_vapi.read()
    core_header = args.core_header.read()
    base_vapi = args.base_vapi.read()
    base_header = args.base_header.read()
    output_dir = Path(args.output_dir)

    toplevel_names = [
        "frida.vala",
        "control-service.vala",
        "portal-service.vala",
        "web-gateway-service.vala",
        "endpoint.vala",
        "file-monitor.vala",
    ]
    toplevel_sources = []
    src_dir = Path(__file__).parent.parent.resolve()
    for name in toplevel_names:
        with open(src_dir / name, 'r', encoding='utf-8') as f:
            toplevel_sources.append(f.read())
    toplevel_code = "\n".join(toplevel_sources)

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

    api = parse_api(api_version, toplevel_code, core_vapi, core_header, base_vapi, base_header)

    if enable_header:
        emit_header(api, output_dir)

    if enable_vapi:
        emit_vapi(api, output_dir)

def emit_header(api, output_dir):
    with open(output_dir / 'frida-core.h', 'w', encoding='utf-8') as output_header_file:
        output_header_file.write("#ifndef __FRIDA_CORE_H__\n#define __FRIDA_CORE_H__\n\n")

        output_header_file.write("#include <glib.h>\n#include <glib-object.h>\n#include <gio/gio.h>\n#include <json-glib/json-glib.h>\n")

        output_header_file.write("\nG_BEGIN_DECLS\n")

        for object_type in api.object_types:
            output_header_file.write("\ntypedef struct _%s %s;" % (object_type.c_name, object_type.c_name))
            if object_type.c_iface_definition is not None:
                output_header_file.write("\ntypedef struct _%sIface %sIface;" % (object_type.c_name, object_type.c_name))
        output_header_file.write("\ntypedef struct _FridaHostSession FridaHostSession;")

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
            if object_type.c_iface_definition is not None:
                sections.append("\n" + object_type.c_iface_definition)
            if len(object_type.c_constructors) > 0:
                sections.append("\n" + "\n".join(object_type.c_constructors))
            if len(object_type.c_getter_prototypes) > 0:
                sections.append("\n" + "\n".join(object_type.c_getter_prototypes))
            if len(object_type.c_method_prototypes) > 0:
                sections.append("\n" + "\n".join(object_type.c_method_prototypes))
            output_header_file.write("\n".join(sections))

        output_header_file.write("\n\n/* Toplevel functions */")
        for func in api.functions:
            output_header_file.write("\n" + func.c_prototype)

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
    with open(output_dir / "frida-core-{0}.vapi".format(api.version), "w", encoding='utf-8') as output_vapi_file:
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

        output_vapi_file.write("\n")
        for func in api.functions:
            output_vapi_file.write("\n" + func.vapi_declaration)

        for enum in api.error_types:
            output_vapi_file.write("\n\n\t%s\n\t\t" % enum.vapi_declaration)
            output_vapi_file.write("\n\t\t".join(enum.vapi_members))
            output_vapi_file.write("\n\t}")

        for enum in api.enum_types:
            output_vapi_file.write("\n\n\t%s\n\t\t" % enum.vapi_declaration)
            output_vapi_file.write("\n\t\t".join(enum.vapi_members))
            output_vapi_file.write("\n\t}")

        output_vapi_file.write("\n}\n")

    with open(output_dir / "frida-core-{0}.deps".format(api.version), "w", encoding='utf-8') as output_deps_file:
        output_deps_file.write("glib-2.0\n")
        output_deps_file.write("gobject-2.0\n")
        output_deps_file.write("gio-2.0\n")

def parse_api(api_version, toplevel_code, core_vapi, core_header, base_vapi, base_header):
    all_headers = core_header + "\n" + base_header

    all_enum_names = [m.group(1) for m in re.finditer(r"^\t+public\s+enum\s+(\w+)\s+", toplevel_code + "\n" + base_vapi, re.MULTILINE)]
    enum_types = []

    base_public_types = {
        "SessionOptions": "SpawnOptions",
        "ScriptOptions": "Script",
        "PeerOptions": "ScriptOptions",
        "Relay": "PeerOptions",
        "PortalOptions": "Relay",
        "RpcClient": "PortalMembership",
        "RpcPeer": "RpcClient",
        "AuthenticationService": "PortalService",
        "StaticAuthenticationService": "AuthenticationService",
    }
    internal_type_prefixes = [
        "Fruity",
        "HostSession",
        "MessageType",
        "ResultCode",
        "SpawnStartState",
        "State",
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
        for m in re.finditer(r"typedef\s+enum\s+.*?\s+(\w+);", all_headers, re.DOTALL):
            if m.group(1) == enum.c_name:
                enum.c_definition = beautify_cenum(m.group(0))
                break

    error_types = [ApiEnum(m.group(1)) for m in re.finditer(r"^\t+public\s+errordomain\s+(\w+)\s+", base_vapi, re.MULTILINE)]
    error_by_name = {}
    for enum in error_types:
        error_by_name[enum.name] = enum
    for enum in error_types:
        for m in re.finditer(r"typedef\s+enum\s+.*?\s+(\w+);", base_header, re.DOTALL):
            if m.group(1) == enum.c_name:
                enum.c_definition = beautify_cenum(m.group(0))
                break

    object_types = parse_vala_object_types(toplevel_code)

    pending_public_types = set(base_public_types.keys())
    base_object_types = parse_vala_object_types(base_vapi)
    while len(pending_public_types) > 0:
        for potential_type in base_object_types:
            name = potential_type.name
            if name in pending_public_types:
                insert_after = base_public_types[name]
                for i, t in enumerate(object_types):
                    if t.name == insert_after:
                        object_types.insert(i + 1, potential_type)
                        pending_public_types.remove(name)

    object_type_by_name = {}
    for klass in object_types:
        object_type_by_name[klass.name] = klass
    seen_cfunctions = set()
    seen_cdelegates = set()
    for object_type in sorted(object_types, key=lambda klass: len(klass.c_name_lc), reverse=True):
        for m in re.finditer(r"^.*?\s+" + object_type.c_name_lc + r"_(\w+)\s+[^;]+;", all_headers, re.MULTILINE):
            method_cprototype = beautify_cprototype(m.group(0))
            if method_cprototype.startswith("VALA_EXTERN "):
                method_cprototype = method_cprototype[12:]
            method_name = m.group(1)
            method_cname_lc = object_type.c_name_lc + '_' + method_name
            if method_cname_lc not in seen_cfunctions:
                seen_cfunctions.add(method_cname_lc)
                if method_name not in ('construct', 'construct_with_host_session', 'get_main_context', 'get_provider', 'get_session') \
                        and not (object_type.name in ("Session", "Script") and method_name == 'get_id'):
                    if (object_type.c_name + '*') in m.group(0):
                        if method_name == 'new' or method_name.startswith('new_'):
                            object_type.c_constructors.append(method_cprototype)
                        elif method_name.startswith('get_') and not any(arg in method_cprototype for arg in ['GAsyncReadyCallback', 'GError ** error']):
                            object_type.property_names.append(method_name[4:])
                            object_type.c_getter_prototypes.append(method_cprototype)
                        else:
                            object_type.method_names.append(method_name)
                            object_type.c_method_prototypes.append(method_cprototype)
                    elif method_name == 'get_type':
                        object_type.c_get_type = method_cprototype.replace("G_GNUC_CONST ;", "G_GNUC_CONST;")
        for d in re.finditer(r"^typedef.+?\(\*(" + object_type.c_name + r".+?)\) \(.+\);$", core_header, re.MULTILINE):
            delegate_cname = d.group(1)
            if delegate_cname not in seen_cdelegates:
                seen_cdelegates.add(delegate_cname)
                object_type.c_delegate_typedefs.append(beautify_cprototype(d.group(0)))
        if object_type.kind == 'interface' and object_type.name != "Injector":
            for m in re.finditer("^(struct _" + object_type.c_name + "Iface {[^}]+};)$", all_headers, re.MULTILINE):
                object_type.c_iface_definition = beautify_cinterface(m.group(1))

    current_enum = None
    current_object_type = None
    ignoring = False
    for line in (core_vapi + base_vapi).split("\n"):
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
                if len(current_object_type.c_constructors) > 0:
                    current_object_type.vapi_constructor = stripped_line
            elif stripped_line.startswith("public signal"):
                current_object_type.vapi_signals.append(stripped_line)
            elif "{ get" in stripped_line:
                name = re.match(r".+?(\w+)\s+{", stripped_line).group(1)
                if name not in ('main_context', 'provider', 'session'):
                    current_object_type.vapi_properties.append(stripped_line)
            else:
                m = re.match(r".+?(\w+)\s+\(", stripped_line)
                if m is not None:
                    name = m.group(1)
                    if not name.startswith("_") and name != 'dispose':
                        current_object_type.vapi_methods.append(stripped_line)
    for object_type in object_types:
        object_type.sort_members()
    for enum in enum_types:
        if enum.vapi_declaration is None:
            m = re.match(r".+\s+(public\s+enum\s+" + enum.name + r"\s+{)(.+?)}", base_vapi, re.MULTILINE | re.DOTALL)
            enum.vapi_declaration = m.group(1)
            enum.vapi_members.extend([line.lstrip() for line in m.group(2).strip().split("\n")])

    functions = [f for f in parse_vapi_functions(base_vapi) if function_is_public(f.name)]
    for f in functions:
        m = re.search(r"^[\w\*]+ frida_{}.+?;".format(f.name), all_headers, re.MULTILINE | re.DOTALL)
        f.c_prototype = beautify_cprototype(m.group(0))

    return ApiSpec(api_version, object_types, functions, enum_types, error_types)

def function_is_public(name):
    return not name.startswith("_") and \
            not name.startswith("throw_") and \
            name not in ("generate_certificate", "get_dbus_context", "make_options_dict", "parse_control_address", "parse_cluster_address", "parse_socket_address")

def parse_vala_object_types(source):
    return [ApiObjectType(m.group(2), m.group(1)) for m in re.finditer(r"^\t+public\s+(class|interface)\s+(\w+)\s+", source, re.MULTILINE)]

def parse_vapi_functions(vapi):
    return [ApiFunction(m.group(1), m.group(0)) for m in re.finditer(r"^\tpublic static .+ (\w+) \(.+;", vapi, re.MULTILINE)]

class ApiSpec:
    def __init__(self, version, object_types, functions, enum_types, error_types):
        self.version = version
        self.object_types = object_types
        self.functions = functions
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
        self.c_constructors = []
        self.c_getter_prototypes = []
        self.c_method_prototypes = []
        self.c_delegate_typedefs = []
        self.c_iface_definition = None
        self.vapi_declaration = None
        self.vapi_signals = []
        self.vapi_properties = []
        self.vapi_constructor = None
        self.vapi_methods = []

    def sort_members(self):
        self.vapi_properties = fuzzysort(self.vapi_properties, self.property_names)
        self.vapi_methods = fuzzysort(self.vapi_methods, self.method_names)

class ApiFunction:
    def __init__(self, name, vapi_declaration):
        self.name = name
        self.c_prototype = None
        self.vapi_declaration = vapi_declaration

    def __repr__(self):
        return "ApiFunction(name=\"{}\")".format(self.name)

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
    result = result.replace("gpointer func_target", "gpointer user_data")
    result = result.replace("_length1", "_length")
    result = result.replace(" _callback_,", " callback,")
    result = result.replace(" _user_data_", " user_data")
    result = result.replace(" _res_", " result")
    return result

def beautify_cinterface(iface):
    lines = iface.split("\n")

    header = lines[0]
    body = ["  " + beautify_cprototype(line.lstrip()) for line in lines[1:-1]]
    footer = lines[-1]

    return "\n".join([header, *body, footer])

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
