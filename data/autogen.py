import os

os.system('gtk-builder-convert.py --skip-windows login.glade login.ui')

f = open('login.ui', 'rb')
s = f.read()
f.close()
os.unlink('login.ui')
print 'Deleted login.ui'

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

code = """\
/* generated from login.glade, do not modify */
namespace Zed.Data.Login {
\tpublic static const string UI_XML = %s;
}
""" % s
f = open('login.vala', 'wb')
f.write(code)
f.close()
print 'Wrote login.vala'

