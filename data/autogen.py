import os

os.system('gtk-builder-convert.py --skip-windows login.glade login.ui')

f = open('login.ui', 'rb')
s = f.read()
f.close()
os.unlink('login.ui')
print 'Deleted login.ui'

s = ''.join(map(lambda v: v.strip(), s.split('\n')))
startpos = s.index('<!--')
endpos = s.index('-->', startpos + 4) + 3
s = s[0:startpos] + s[endpos:]

code = """\
/* generated from login.glade, do not modify */
namespace Zed.Data.Login {
\tpublic static const string UI_XML = "%s";
}
""" % s.replace('"', '\\"')
f = open('login.vala', 'wb')
f.write(code)
f.close()
print 'Wrote login.vala'

