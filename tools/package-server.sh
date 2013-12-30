#!/bin/sh

if [ -z "$FRIDA_VERSION" ]; then
  echo "FRIDA_VERSION must be set" > /dev/stderr
  exit 1
fi

if [ -z "$FRIDA_SERVER" -o ! -f "$FRIDA_SERVER" ]; then
  echo "FRIDA_SERVER must be set" > /dev/stderr
  exit 2
fi

tmpdir="$(mktemp -d /tmp/package-server.XXXXXX)"

mkdir -p "$tmpdir/usr/sbin/"
cp "$FRIDA_SERVER" "$tmpdir/usr/sbin/frida-server"
chmod 755 "$tmpdir/usr/sbin/frida-server"

mkdir -p "$tmpdir/Library/LaunchDaemons/"
cat >"$tmpdir/Library/LaunchDaemons/com.tillitech.frida-server.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>Label</key>
        <string>com.tillitech.frida-server</string>
        <key>ProgramArguments</key>
        <array>
                <string>/usr/sbin/frida-server</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
        <key>UserName</key>
        <string>root</string>
</dict>
</plist>
EOF

mkdir -p "$tmpdir/DEBIAN/"
cat >"$tmpdir/DEBIAN/control" <<EOF
Package: com.tillitech.frida-server
Name: frida
Version: $FRIDA_VERSION
Priority: optional
Size: 12288000
Installed-Size: 12000
Architecture: iphoneos-arm
Description: Frida is an open-source toolkit for interactive
 and scriptable reverse-engineering.
Homepage: http://frida.github.io/
Maintainer: Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
Author: Frida Developers <ole.andre.ravnas@tillitech.com>
Section: Development
EOF

dpkg-deb -c "$tmpdir" frida_${FRIDA_VERSION}_iphoneos-arm.deb

rm -rf "$tmpdir"
