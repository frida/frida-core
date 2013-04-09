#!/usr/bin/env python

import re
import sys

class ApiClass:
    def __init__(self, name):
        self.name = name
        self.cname = 'Frida' + name
        self.cname_lc = camel_identifier_to_lc(self.cname)
        self.constructor = None
        self.getters = []
        self.methods = []

def camel_identifier_to_lc(camel_identifier):
    result = ""
    for c in camel_identifier:
        if c.istitle() and len(result) > 0:
            result += '_'
        result += c.lower()
    return result

def beautify_cprototype(cprototype):
    result = re.sub(r"([a-z])\*", r"\1 *", cprototype)
    result = result.replace("_length1", "_length")
    result = result.replace(" _callback_,", " callback,")
    result = result.replace(" _user_data_", " user_data")
    result = result.replace(" _res_", " result")
    return result

if __name__ == '__main__':
    with open(sys.argv[1]) as api_vala_file:
        api_vala = api_vala_file.read()
        with open(sys.argv[2]) as core_header_file:
            core_header = core_header_file.read()

            api_classes = [ApiClass(m.group(1)) for m in re.finditer(r"^\t+public\s+class\s+(\w+)\s+", api_vala, re.MULTILINE)]
            seen_cfunctions = {}
            for klass in sorted(api_classes, key=lambda klass: len(klass.cname_lc), reverse=True):
                for m in re.finditer(r"^.*?\s+" + klass.cname_lc + r"_(\w+)\s+.*;", core_header, re.MULTILINE):
                    method_cprototype = beautify_cprototype(m.group(0))
                    method_name = m.group(1)
                    method_cname_lc = klass.cname_lc + '_' + method_name
                    if method_cname_lc not in seen_cfunctions:
                        seen_cfunctions[method_cname_lc] = True
                        if method_name not in ('get_type', 'construct', 'get_main_context', 'get_provider', 'get_session'):
                            if (klass.cname + '*') in m.group(0):
                                if method_name == 'new':
                                    if not klass.name.endswith("List") and method_cprototype.endswith("(void);"):
                                        klass.constructor = method_cprototype
                                elif method_name.startswith('get_'):
                                    klass.getters.append(method_cprototype)
                                else:
                                    klass.methods.append(method_cprototype)

            with open(sys.argv[3], 'wb') as output_header_file:
                output_header_file.write("#ifndef __FRIDA_CORE_H__\n#define __FRIDA_CORE_H__\n\n\n")

                output_header_file.write("#include <glib.h>\n#include <glib-object.h>\n#include <gio/gio.h>\n\n")

                for klass in api_classes:
                    output_header_file.write("\ntypedef struct _%s %s;" % (klass.cname, klass.cname))

                output_header_file.write("\n\n\n/*\n * Library lifetime\n */\n\n")
                output_header_file.write("void frida_init (void);\n")
                output_header_file.write("void frida_deinit (void);\n")
                output_header_file.write("GMainContext * frida_get_main_context (void);")

                for klass in api_classes:
                    output_header_file.write("\n\n\n/*\n * %s\n */" % klass.name)
                    if klass.constructor is not None:
                        output_header_file.write("\n\n" + klass.constructor)
                    if len(klass.getters) > 0:
                        output_header_file.write("\n\n" + "\n".join(klass.getters))
                    if len(klass.methods) > 0:
                        output_header_file.write("\n\n" + "\n".join(klass.methods))

                output_header_file.write("\n\n#endif\n")
