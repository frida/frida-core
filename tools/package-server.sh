#!/bin/sh

if [ -z "$FRIDA_TOOLCHAIN" ]; then
  echo "FRIDA_TOOLCHAIN must be set" > /dev/stderr
  exit 1
fi

if [ -z "$FRIDA_VERSION" ]; then
  echo "FRIDA_VERSION must be set" > /dev/stderr
  exit 2
fi

if [ $# -ne 2 ]; then
  echo "Usage: $0 frida-server output.deb" > /dev/stderr
  exit 3
fi
FRIDA_SERVER="$1"
if [ ! -f "$FRIDA_SERVER" ]; then
  echo "$FRIDA_SERVER: not found" > /dev/stderr
  exit 4
fi
OUTPUT_DEB="$2"

tmpdir="$(mktemp -d /tmp/package-server.XXXXXX)"

mkdir -p "$tmpdir/usr/sbin/"
cp "$FRIDA_SERVER" "$tmpdir/usr/sbin/frida-server"
chmod 755 "$tmpdir/usr/sbin/frida-server"

mkdir -p "$tmpdir/Library/LaunchDaemons/"
cat >"$tmpdir/Library/LaunchDaemons/re.frida.server.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>re.frida.server</string>
	<key>Program</key>
	<string>/usr/sbin/frida-server</string>
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
chmod 644 "$tmpdir/Library/LaunchDaemons/re.frida.server.plist"

mkdir -p "$tmpdir/DEBIAN/"
cat >"$tmpdir/DEBIAN/control" <<EOF
Package: re.frida.server
Name: Frida
Version: $FRIDA_VERSION
Priority: optional
Size: 20942682
Installed-Size: 51000
Architecture: iphoneos-arm
Description: Inject JavaScript to explore iOS apps over USB.
Homepage: http://frida.github.io/
Maintainer: Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
Author: Frida Developers <ole.andre.ravnas@tillitech.com>
Section: Development
EOF
chmod 644 "$tmpdir/DEBIAN/control"

cat >"$tmpdir/DEBIAN/extrainst_" <<EOF
#!/bin/sh

if [[ \$1 == upgrade ]]; then
  /bin/launchctl unload /Library/LaunchDaemons/re.frida.server.plist
fi

if [[ \$1 == install || \$1 == upgrade ]]; then
  /bin/launchctl load /Library/LaunchDaemons/re.frida.server.plist
fi

exit 0
EOF
chmod 755 "$tmpdir/DEBIAN/extrainst_"
cat >"$tmpdir/DEBIAN/prerm" <<EOF
#!/bin/sh

if [[ \$1 == remove || \$1 == purge ]]; then
  /bin/launchctl unload /Library/LaunchDaemons/re.frida.server.plist
fi

exit 0
EOF
chmod 755 "$tmpdir/DEBIAN/prerm"

sudo chown -R 0:0 "$tmpdir"
sudo $FRIDA_TOOLCHAIN/bin/dpkg-deb -b "$tmpdir" "$OUTPUT_DEB"
sudo chown -R $(whoami) "$tmpdir" "$OUTPUT_DEB"

rm -rf "$tmpdir"
