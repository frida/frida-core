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
executable="$1"
if [ ! -f "$executable" ]; then
  echo "$executable: not found" > /dev/stderr
  exit 4
fi
output_deb="$2"

if file "$executable" | grep -q arm64e; then
  pkg_id="re.frida.server64"
  pkg_name="Frida for A12+ devices"
  pkg_conflicts="re.frida.server, re.frida.server32"
elif file "$executable" | grep -q arm64; then
  pkg_id="re.frida.server"
  pkg_name="Frida for pre-A12 devices"
  pkg_conflicts="re.frida.server32, re.frida.server64"
else
  pkg_id="re.frida.server32"
  pkg_name="Frida for 32-bit devices"
  pkg_conflicts="re.frida.server, re.frida.server64"
fi

tmpdir="$(mktemp -d /tmp/package-server.XXXXXX)"

mkdir -p "$tmpdir/usr/sbin/"
cp "$executable" "$tmpdir/usr/sbin/frida-server"
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
	<key>EnvironmentVariables</key>
	<dict>
		<key>_MSSafeMode</key>
		<string>1</string>
	</dict>
	<key>UserName</key>
	<string>root</string>
	<key>RunAtLoad</key>
	<true/>
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
Package: $pkg_id
Name: $pkg_name
Version: $FRIDA_VERSION
Priority: optional
Size: 1337
Installed-Size: $installed_size
Architecture: iphoneos-arm
Description: Inject JavaScript to explore iOS apps over USB.
Homepage: https://www.frida.re/
Maintainer: Ole André Vadla Ravnås <oleavr@nowsecure.com>
Author: Frida Developers <oleavr@nowsecure.com>
Section: Development
Conflicts: $pkg_conflicts
EOF
chmod 644 "$tmpdir/DEBIAN/control"

cat >"$tmpdir/DEBIAN/extrainst_" <<EOF
#!/bin/sh

if [[ \$1 == upgrade ]]; then
  launchctl unload /Library/LaunchDaemons/re.frida.server.plist
fi

if [[ \$1 == install || \$1 == upgrade ]]; then
  launchctl load /Library/LaunchDaemons/re.frida.server.plist
fi

exit 0
EOF
chmod 755 "$tmpdir/DEBIAN/extrainst_"
cat >"$tmpdir/DEBIAN/prerm" <<EOF
#!/bin/sh

if [[ \$1 == remove || \$1 == purge ]]; then
  launchctl unload /Library/LaunchDaemons/re.frida.server.plist
fi

exit 0
EOF
chmod 755 "$tmpdir/DEBIAN/prerm"

$FRIDA_TOOLCHAIN/bin/dpkg-deb -b "$tmpdir" "$output_deb"
package_size=$(expr $(du -sk "$output_deb" | cut -f1) \* 1024)

sudo chown -R 0:0 "$tmpdir"
sudo sed \
  -i "" \
  -e "s,^Size: 1337$,Size: $package_size,g" \
  "$tmpdir/DEBIAN/control"
sudo $FRIDA_TOOLCHAIN/bin/dpkg-deb -b "$tmpdir" "$output_deb"
sudo chown -R $(whoami) "$tmpdir" "$output_deb"

rm -rf "$tmpdir"
