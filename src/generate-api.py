#!/usr/bin/env python

import os
import re
import sys

class ApiClass:
    def __init__(self, name):
        self.name = name
        self.name_lc = camel_identifier_to_lc(self.name)
        self.name_uc = camel_identifier_to_uc(self.name)
        self.property_names = []
        self.method_names = []
        self.c_name = 'Frida' + name
        self.c_name_lc = camel_identifier_to_lc(self.c_name)
        self.c_get_type = None
        self.c_constructor = None
        self.c_getter_prototypes = []
        self.c_method_prototypes = []
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

def beautify_cprototype(cprototype):
    result = re.sub(r"([a-z0-9])\*", r"\1 *", cprototype)
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
    with open(sys.argv[1]) as api_vala_file:
        api_vala = api_vala_file.read()
        with open(sys.argv[3]) as core_header_file:
            core_header = core_header_file.read()

            api_classes = [ApiClass(m.group(1)) for m in re.finditer(r"^\t+public\s+class\s+(\w+)\s+", api_vala, re.MULTILINE)]
            class_by_name = {}
            for klass in api_classes:
                class_by_name[klass.name] = klass
            seen_cfunctions = {}
            for klass in sorted(api_classes, key=lambda klass: len(klass.c_name_lc), reverse=True):
                for m in re.finditer(r"^.*?\s+" + klass.c_name_lc + r"_(\w+)\s+.*;", core_header, re.MULTILINE):
                    method_cprototype = beautify_cprototype(m.group(0))
                    method_name = m.group(1)
                    method_cname_lc = klass.c_name_lc + '_' + method_name
                    if method_cname_lc not in seen_cfunctions:
                        seen_cfunctions[method_cname_lc] = True
                        if method_name not in ('construct', 'get_main_context', 'get_provider', 'get_session'):
                            if (klass.c_name + '*') in m.group(0):
                                if method_name == 'new':
                                    if not klass.name.endswith("List") and method_cprototype.endswith("(void);"):
                                        klass.c_constructor = method_cprototype
                                elif method_name.startswith('get_'):
                                    klass.property_names.append(method_name[4:])
                                    klass.c_getter_prototypes.append(method_cprototype)
                                else:
                                    klass.method_names.append(method_name)
                                    klass.c_method_prototypes.append(method_cprototype)
                            elif method_name == 'get_type':
                                klass.c_get_type = method_cprototype

            with open(sys.argv[2]) as core_vapi_file:
                current_class = None
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
                            if stripped_line.startswith("[CCode (cprefix") or stripped_line.startswith("public interface") or stripped_line.startswith("public abstract"):
                                ignoring = True
                            elif stripped_line.startswith("public class"):
                                name = re.match(r"^public class (\w+) ", stripped_line).group(1)
                                if name not in class_by_name:
                                    ignoring = True
                                else:
                                    current_class = class_by_name[name]
                                    current_class.vapi_declaration = stripped_line
                            elif stripped_line == "}":
                                current_class = None
                    elif current_class is not None and stripped_line.startswith("public"):
                        if stripped_line.startswith("public " + current_class.name + " ("):
                            if current_class.c_constructor is not None:
                                current_class.vapi_constructor = stripped_line
                        elif stripped_line.startswith("public signal"):
                            current_class.vapi_signals.append(stripped_line)
                        elif "{ get" in stripped_line:
                            name = re.match(r".+?(\w+)\s+{", stripped_line).group(1)
                            if name not in ('main_context', 'provider', 'session'):
                                current_class.vapi_properties.append(stripped_line)
                        else:
                            name = re.match(r".+?(\w+)\s+\(", stripped_line).group(1)
                            if not name.startswith("_") and name != 'dispose':
                                current_class.vapi_methods.append(stripped_line)
                for klass in api_classes:
                    klass.sort_members()

            with open(os.path.join(sys.argv[4], 'frida-core-1.0.deps'), 'wb') as output_deps_file:
                output_deps_file.write("glib-2.0\n")
                output_deps_file.write("gobject-2.0\n")
                output_deps_file.write("gio-2.0\n")

            with open(os.path.join(sys.argv[4], 'frida-core-1.0.vapi'), 'wb') as output_vapi_file:
                output_vapi_file.write("[CCode (cheader_filename = \"frida-core.h\", cprefix = \"Frida\", lower_case_cprefix = \"frida_\")]")
                output_vapi_file.write("\nnamespace Frida {")
                output_vapi_file.write("\n\tpublic static void init ();")
                output_vapi_file.write("\n\tpublic static void shutdown ();")
                output_vapi_file.write("\n\tpublic static void deinit ();")
                output_vapi_file.write("\n\tpublic static GLib.MainContext get_main_context ();")

                for klass in api_classes:
                    output_vapi_file.write("\n\n\t%s" % klass.vapi_declaration)
                    sections = []
                    if len(klass.vapi_properties) > 0:
                        sections.append("\n\t\t" + "\n\t\t".join(klass.vapi_properties))
                    if klass.vapi_constructor is not None:
                        sections.append("\n\t\t" + klass.vapi_constructor)
                    if len(klass.vapi_methods) > 0:
                        sections.append("\n\t\t" + "\n\t\t".join(klass.vapi_methods))
                    if len(klass.vapi_signals) > 0:
                        sections.append("\n\t\t" + "\n\t\t".join(klass.vapi_signals))
                    output_vapi_file.write("\n".join(sections))
                    output_vapi_file.write("\n\t}")

                output_vapi_file.write("\n}\n")

            with open(os.path.join(sys.argv[4], 'frida-core.h'), 'wb') as output_header_file:
                output_header_file.write("#ifndef __FRIDA_CORE_H__\n#define __FRIDA_CORE_H__\n\n")

                output_header_file.write("#include <glib.h>\n#include <glib-object.h>\n#include <gio/gio.h>\n")

                output_header_file.write("\nG_BEGIN_DECLS\n")

                for klass in api_classes:
                    output_header_file.write("\ntypedef struct _%s %s;" % (klass.c_name, klass.c_name))

                output_header_file.write("\n\n/* Library lifetime */")
                output_header_file.write("\nvoid frida_init (void);")
                output_header_file.write("\nvoid frida_shutdown (void);")
                output_header_file.write("\nvoid frida_deinit (void);")
                output_header_file.write("\nGMainContext * frida_get_main_context (void);")

                for klass in api_classes:
                    output_header_file.write("\n\n/* %s */" % klass.name)
                    sections = []
                    if klass.c_constructor is not None:
                        sections.append("\n" + klass.c_constructor)
                    if len(klass.c_getter_prototypes) > 0:
                        sections.append("\n" + "\n".join(klass.c_getter_prototypes))
                    if len(klass.c_method_prototypes) > 0:
                        sections.append("\n" + "\n".join(klass.c_method_prototypes))
                    output_header_file.write("\n".join(sections))

                output_header_file.write("\n\n/* GTypes */")
                for klass in api_classes:
                    if klass.c_get_type is not None:
                        output_header_file.write("\n" + klass.c_get_type)

                output_header_file.write("\n\n/* Macros */")
                macros = []
                for klass in api_classes:
                    macros.append("""#define FRIDA_TYPE_%(name_uc)s (frida_%(name_lc)s_get_type ())
#define FRIDA_%(name_uc)s(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), FRIDA_TYPE_%(name_uc)s, Frida%(name)s))
#define FRIDA_%(name_uc)s_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass), FRIDA_TYPE_%(name_uc)s, Frida%(name)sClass))
#define FRIDA_IS_%(name_uc)s(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), FRIDA_TYPE_%(name_uc)s))
#define FRIDA_IS_%(name_uc)s_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), FRIDA_TYPE_%(name_uc)s))
#define FRIDA_%(name_uc)s_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), FRIDA_TYPE_%(name_uc)s, Frida%(name)sClass))""" \
                        % { 'name': klass.name, 'name_lc': klass.name_lc, 'name_uc': klass.name_uc })
                output_header_file.write("\n" + "\n\n".join(macros))

                output_header_file.write("\n\nG_END_DECLS")

                output_header_file.write("\n\n#endif\n")
