import glob
import os
import os.path
import sys

def glade_to_inline_ui_string(name):
    glade_fname = name + '.glade'
    ui_fname = name + '.ui'

    os.system('gtk-builder-convert.py --skip-windows %s %s' % (glade_fname, ui_fname))

    f = open(ui_fname, 'rb')
    s = f.read()
    f.close()
    os.unlink(ui_fname)
    print 'Deleted', ui_fname

    def transform_line(line):
        indent = 0
        for c in line:
            if c.isspace():
                indent += 1
            else:
                break
        return (((indent / 2) - 1) * '\t') + '"' + line[indent:].rstrip().replace('"', '\\"') + '" +'

    startpos = s.index('<!--')
    endpos = s.index('-->', startpos + 4) + 3
    s = s[0:startpos] + '\n' + s[endpos:]
    startpos = s.index('<interface>')
    endpos = startpos + 11
    s = s[0:startpos].rstrip() + '\n      ' + s[startpos:endpos] + s[endpos:].strip()

    lines = s.split('\n')
    lines = filter(lambda line: '<property name="response_id">' not in line, lines)
    s = '\n'.join(map(transform_line, lines))
    s = s.rstrip('+ ')

    return s

os.chdir(os.path.dirname(sys.argv[0]))

code = """\
/* generated file, do not modify */
namespace Zed.Data.Ui {"""
names = map(lambda name: os.path.splitext(name)[0], glob.glob('*.glade'))
for name in names:
    code += '\n\tpublic static const string %s_XML = %s;\n' % (name.upper(), glade_to_inline_ui_string(name))

code += '}'

f = open('ui.vala', 'wb')
f.write(code)
f.close()
print
print 'Wrote ui.vala'

