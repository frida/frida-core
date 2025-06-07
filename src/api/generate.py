from __future__ import annotations
import argparse
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
import re
from typing import List, Set
import xml.etree.ElementTree as ET

CORE_NAMESPACE = "http://www.gtk.org/introspection/core/1.0"
C_NAMESPACE = "http://www.gtk.org/introspection/c/1.0"
GLIB_NAMESPACE = "http://www.gtk.org/introspection/glib/1.0"
GIR_NAMESPACES = {
    "": CORE_NAMESPACE,
    "c": C_NAMESPACE,
    "glib": GLIB_NAMESPACE,
}

CORE_TAG_IMPLEMENTS = f"{{{CORE_NAMESPACE}}}implements"
CORE_TAG_FIELD = f"{{{CORE_NAMESPACE}}}field"
CORE_TAG_CONSTRUCTOR = f"{{{CORE_NAMESPACE}}}constructor"
CORE_TAG_METHOD = f"{{{CORE_NAMESPACE}}}method"

OBJECT_TYPE_PATTERN = re.compile(r"\bpublic\s+(sealed )?(class|interface)\s+(\w+)\b")

def main():
    parser = argparse.ArgumentParser(description="Generate refined Frida API definitions")
    parser.add_argument('--output', dest='output_type', choices=['bundle', 'header', 'gir', 'vapi', 'vapi-stamp'], default='bundle')
    parser.add_argument('frida_version', metavar='frida-version', type=str)
    parser.add_argument('frida_major_version', metavar='frida-major-version', type=str)
    parser.add_argument('frida_minor_version', metavar='frida-minor-version', type=str)
    parser.add_argument('frida_micro_version', metavar='frida-micro-version', type=str)
    parser.add_argument('frida_nano_version', metavar='frida-nano-version', type=str)
    parser.add_argument('api_version', metavar='api-version', type=str)
    parser.add_argument('core_header', metavar='/path/to/frida-core.h', type=argparse.FileType('r', encoding='utf-8'))
    parser.add_argument('core_gir', metavar='/path/to/Frida-x.y.gir', type=argparse.FileType('r', encoding='utf-8'))
    parser.add_argument('core_vapi', metavar='/path/to/frida-core.vapi', type=argparse.FileType('r', encoding='utf-8'))
    parser.add_argument('base_header', metavar='/path/to/frida-base.h', type=argparse.FileType('r', encoding='utf-8'))
    parser.add_argument('base_gir', metavar='/path/to/FridaBase-x.y.gir', type=argparse.FileType('r', encoding='utf-8'))
    parser.add_argument('base_vapi', metavar='/path/to/frida-base.vapi', type=argparse.FileType('r', encoding='utf-8'))
    parser.add_argument('output_dir', metavar='/output/dir')

    args = parser.parse_args()

    output_type = args.output_type
    frida_version = args.frida_version
    frida_version_components = (
        args.frida_major_version,
        args.frida_minor_version,
        args.frida_micro_version,
        args.frida_nano_version,
    )
    api_version = args.api_version
    core_header = args.core_header.read()
    core_gir = args.core_gir.read()
    core_vapi = args.core_vapi.read()
    base_header = args.base_header.read()
    base_gir = args.base_gir.read()
    base_vapi = args.base_vapi.read()
    output_dir = Path(args.output_dir)

    if output_type == 'vapi-stamp':
        (output_dir / f"frida-core-{api_version}.vapi.stamp").write_bytes(b"")
        return

    toplevel_names = [
        "frida.vala",
        "control-service.vala",
        "portal-service.vala",
        "file-monitor.vala",
        Path("compiler") / "compiler.vala",
    ]
    toplevel_sources = []
    src_dir = Path(__file__).parent.parent.resolve()
    for name in toplevel_names:
        toplevel_sources.append((src_dir / name).read_text(encoding='utf-8'))
    toplevel_code = "\n".join(toplevel_sources)

    enable_header = False
    enable_gir = False
    enable_vapi = False
    if output_type == 'bundle':
        enable_header = True
        enable_gir = True
        enable_vapi = True
    elif output_type == 'header':
        enable_header = True
    elif output_type == 'gir':
        enable_gir = True
    elif output_type == 'vapi':
        enable_vapi = True

    api = parse_api(frida_version, frida_version_components, api_version, toplevel_code, core_header, core_vapi, base_header, base_vapi)

    if enable_header:
        emit_header(api, output_dir)

    if enable_gir:
        emit_gir(api, core_gir, base_gir, output_dir)

    if enable_vapi:
        emit_vapi(api, output_dir)

def emit_header(api, output_dir):
    with OutputFile(output_dir / 'frida-core.h') as output_header_file:
        output_header_file.write("#ifndef __FRIDA_CORE_H__\n#define __FRIDA_CORE_H__\n\n")

        output_header_file.write("#include <glib.h>\n#include <glib-object.h>\n#include <gio/gio.h>\n#include <json-glib/json-glib.h>\n\n")

        output_header_file.write(f"#define FRIDA_VERSION \"{api.frida_version}\"\n\n")

        for name, value in zip(['MAJOR', 'MINOR', 'MICRO', 'NANO'], api.frida_version_components):
            output_header_file.write(f"#define FRIDA_{name}_VERSION {value}\n")

        output_header_file.write("""
#define FRIDA_CHECK_VERSION(maj, min, mic) \\
    (FRIDA_CURRENT_VERSION >= FRIDA_VERSION_ENCODE ((maj), (min), (mic)))

#define FRIDA_CURRENT_VERSION \\
    FRIDA_VERSION_ENCODE (    \\
        FRIDA_MAJOR_VERSION,  \\
        FRIDA_MINOR_VERSION,  \\
        FRIDA_MICRO_VERSION)

#define FRIDA_VERSION_ENCODE(maj, min, mic) \\
    (((maj) * 1000000U) + ((min) * 1000U) + (mic))
""")

        output_header_file.write("\nG_BEGIN_DECLS\n")

        for object_type in api.object_types:
            output_header_file.write("\ntypedef struct _%s %s;" % (object_type.c_name, object_type.c_name))
            if object_type.c_iface_definition is not None:
                output_header_file.write("\ntypedef struct _%sIface %sIface;" % (object_type.c_name, object_type.c_name))

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

def emit_gir(api: ApiSpec, core_gir: str, base_gir: str, output_dir: Path) -> str:
    ET.register_namespace("", CORE_NAMESPACE)
    ET.register_namespace("c", C_NAMESPACE)
    ET.register_namespace("glib", GLIB_NAMESPACE)

    core_tree = ET.ElementTree(ET.fromstring(core_gir))
    base_tree = ET.ElementTree(ET.fromstring(base_gir))

    core_root = core_tree.getroot()
    base_root = base_tree.getroot()

    merged_root = ET.Element(core_root.tag, core_root.attrib)

    for elem in core_root.findall("include", GIR_NAMESPACES):
        name = elem.get("name")
        if name in {"GLib", "GObject", "Gio"}:
            merged_root.append(elem)

    for tag in ["package", "c:include"]:
        for elem in core_root.findall(tag, GIR_NAMESPACES):
            merged_root.append(elem)

    core_namespace = core_root.find("namespace", GIR_NAMESPACES)
    merged_namespace = ET.SubElement(merged_root, core_namespace.tag, core_namespace.attrib)

    object_type_names = {obj.name for obj in api.object_types}
    enum_type_names = {enum.name for enum in api.enum_types}
    error_type_names = {error.name for error in api.error_types}

    def merge_and_transform_elements(tag_name: str, spec_set: Set[str]):
        core_elements = filter_elements(core_root.findall(f".//{tag_name}", GIR_NAMESPACES), spec_set)
        base_elements = filter_elements(base_root.findall(f".//{tag_name}", GIR_NAMESPACES), spec_set)
        for elem in core_elements + base_elements:
            if tag_name == "class":
                for child in list(elem):
                    if (child.tag == CORE_TAG_IMPLEMENTS and child.get("name") == "FridaBase.AgentMessageSink") \
                            or child.tag == CORE_TAG_FIELD \
                            or child.get("name").startswith("_"):
                        elem.remove(child)
            merged_namespace.append(elem)

    merge_and_transform_elements("class", object_type_names)
    merge_and_transform_elements("interface", object_type_names)
    merge_and_transform_elements("enumeration", enum_type_names | error_type_names)

    ET.indent(merged_root, space="  ")
    result = ET.tostring(merged_root,
                         encoding="unicode",
                         xml_declaration=True)
    result = result.replace("FridaBase.", "Frida.")
    with OutputFile(output_dir / f"Frida-{api.version}.gir") as output_gir:
        output_gir.write(result)

def filter_elements(elements: List[ET.Element], spec_set: Set[str]):
    return [elem for elem in elements if elem.get("name") in spec_set]

def emit_vapi(api, output_dir):
    with OutputFile(output_dir / f"frida-core-{api.version}.vapi") as output_vapi_file:
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

    with OutputFile(output_dir / f"frida-core-{api.version}.deps") as output_deps_file:
        output_deps_file.write("glib-2.0\n")
        output_deps_file.write("gobject-2.0\n")
        output_deps_file.write("gio-2.0\n")

def parse_api(frida_version, frida_version_components, api_version, toplevel_code, core_header, core_vapi, base_header, base_vapi):
    all_headers = core_header + "\n" + base_header

    all_enum_names = [m.group(1) for m in re.finditer(r"^\t+public\s+enum\s+(\w+)\s+", toplevel_code + "\n" + base_vapi, re.MULTILINE)]
    enum_types = []

    base_public_types = {
        "FrontmostQueryOptions": "SpawnOptions",
        "ApplicationQueryOptions": "FrontmostQueryOptions",
        "ProcessQueryOptions": "ApplicationQueryOptions",
        "SessionOptions": "ProcessQueryOptions",
        "ScriptOptions": "Script",
        "SnapshotOptions": "Script",
        "PeerOptions": "ScriptOptions",
        "Relay": "PeerOptions",
        "PortalOptions": "Relay",
        "RpcClient": "PortalMembership",
        "RpcPeer": "RpcClient",
        "EndpointParameters": "PortalService",
        "AuthenticationService": "EndpointParameters",
        "StaticAuthenticationService": "AuthenticationService",
    }
    internal_type_prefixes = [
        "AgentMessageKind",
        "Fruity",
        "HostSession",
        "MessageType",
        "PeerSetup",
        "PortConflictBehavior",
        "ResultCode",
        "SpawnStartState",
        "State",
        "StringTerminator",
        "UnloadPolicy",
        "WebService",
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
                if method_name != 'construct':
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
        if object_type.kind == 'interface':
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
                if stripped_line.startswith("public abstract") \
                        or stripped_line.startswith("public class Promise") \
                        or stripped_line.startswith("public interface Future") \
                        or stripped_line.startswith("public class CF"):
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
                elif (match := OBJECT_TYPE_PATTERN.match(stripped_line)) is not None:
                    name = match.group(3)
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

    return ApiSpec(frida_version, frida_version_components, api_version, object_types, functions, enum_types, error_types)

def function_is_public(name):
    return not name.startswith("_") and \
            not name.startswith("throw_") and \
            name not in [
                "generate_certificate",
                "get_dbus_context",
                "invalidate_dbus_context",
                "make_parameters_dict",
                "compute_system_parameters",
                "parse_control_address",
                "parse_cluster_address",
                "parse_socket_address",
                "negotiate_connection"
            ]

def parse_vala_object_types(source) -> List[ApiObjectType]:
    return [ApiObjectType(m.group(3), m.group(2)) for m in OBJECT_TYPE_PATTERN.finditer(source, re.MULTILINE)]

def parse_vapi_functions(vapi) -> List[ApiFunction]:
    return [ApiFunction(m.group(1), m.group(0)) for m in re.finditer(r"^\tpublic static .+ (\w+) \(.+;", vapi, re.MULTILINE)]

@dataclass
class ApiSpec:
    frida_version: str
    frida_version_components: List[int]
    version: str
    object_types: List[ApiObjectType]
    functions: List[ApiFunction]
    enum_types: List[ApiEnum]
    error_types: List[ApiEnum]

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

class OutputFile:
    def __init__(self, output_path):
        self._output_path = output_path
        self._io = StringIO()

    def __enter__(self):
        return self._io

    def __exit__(self, *exc):
        result = self._io.getvalue()
        if self._output_path.exists():
            existing_contents = self._output_path.read_text(encoding='utf-8')
            if existing_contents == result:
                return False
        self._output_path.write_text(result, encoding='utf-8')
        return False


if __name__ == '__main__':
    main()
