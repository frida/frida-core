#!/bin/sh

if [ -z "$FRIDA_VERSION" ]; then
  echo "FRIDA_VERSION must be set" > /dev/stderr
  exit 2
fi

if [ $# -ne 3 ]; then
  echo "Usage: $0 arch path/to/prefix output.deb" > /dev/stderr
  exit 3
fi
arch=$1
prefix=$2
output_deb=$3

executable=$prefix/usr/bin/frida-server
if [ ! -f "$executable" ]; then
  echo "$executable: not found" > /dev/stderr
  exit 4
fi

agent=$prefix/usr/lib/frida/frida-agent.dylib
if [ ! -f "$agent" ]; then
  echo "$agent: not found" > /dev/stderr
  exit 5
fi

tmpdir="$(mktemp -d /tmp/package-server.XXXXXX)"

mkdir -p "$tmpdir/usr/sbin/"
cp "$executable" "$tmpdir/usr/sbin/frida-server"
chmod 755 "$tmpdir/usr/sbin/frida-server"

mkdir -p "$tmpdir/usr/lib/frida/"
cp "$agent" "$tmpdir/usr/lib/frida/frida-agent.dylib"
chmod 755 "$tmpdir/usr/lib/frida/frida-agent.dylib"

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
	<key>EnvironmentVariables</key>
	<dict>
		<key>_MSSafeMode</key>
		<string>1</string>
	</dict>
	<key>UserName</key>
	<string>root</string>
	<key>POSIXSpawnType</key>
	<string>Interactive</string>
	<key>RunAtLoad</key>
	<true/>
	<key>LimitLoadToSessionType</key>
	<string>System</string>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>5</integer>
	<key>ExecuteAllowed</key>
	<true/>
</dict>
</plist>
EOF
chmod 644 "$tmpdir/Library/LaunchDaemons/re.frida.server.plist"

installed_size=$(du -sk "$tmpdir" | cut -f1)

mkdir -p "$tmpdir/DEBIAN/"
cat >"$tmpdir/DEBIAN/control" <<EOF
Package: re.frida.server
Name: Frida
Version: $FRIDA_VERSION
Priority: optional
Size: 1337
Installed-Size: $installed_size
Architecture: $arch
Description: Observe and reprogram running programs.
Homepage: https://frida.re/
Maintainer: Ole André Vadla Ravnås <oleavr@nowsecure.com>
Author: Frida Developers <oleavr@nowsecure.com>
Section: Development
Conflicts: re.frida.server64
EOF
chmod 644 "$tmpdir/DEBIAN/control"

cat >"$tmpdir/DEBIAN/extrainst_" <<EOF
#!/bin/sh

if [ "\$1" = upgrade ]; then
  launchctl unload /Library/LaunchDaemons/re.frida.server.plist
fi

if [ "\$1" = install ] || [ "\$1" = upgrade ]; then
  launchctl load /Library/LaunchDaemons/re.frida.server.plist
fi

exit 0
EOF
chmod 755 "$tmpdir/DEBIAN/extrainst_"
cat >"$tmpdir/DEBIAN/prerm" <<EOF
#!/bin/sh

if [ "\$1" = remove ] || [ "\$1" = purge ]; then
  launchctl unload /Library/LaunchDaemons/re.frida.server.plist
fi

exit 0
EOF
chmod 755 "$tmpdir/DEBIAN/prerm"

dpkg_options="-Zxz --root-owner-group"

dpkg-deb $dpkg_options --build "$tmpdir" "$output_deb"
package_size=$(expr $(du -sk "$output_deb" | cut -f1) \* 1024)

sed \
  -e "s,^Size: 1337$,Size: $package_size,g" \
  "$tmpdir/DEBIAN/control" > "$tmpdir/DEBIAN/control_"
mv "$tmpdir/DEBIAN/control_" "$tmpdir/DEBIAN/control"
dpkg-deb $dpkg_options --build "$tmpdir" "$output_deb"

rm -rf "$tmpdir"
