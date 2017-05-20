#!/bin/sh

host_os="$1"
server_binary="$2"
server_entitlements="$3"
signed_server_binary="$4"
strip_binary="$5"
strip_enabled="$6"

if [ -z "$CODESIGN" ]; then
  echo "CODESIGN not set"
  exit 1
fi

case $host_os in
  macos)
    if [ -z "$MAC_CERTID" ]; then
      echo "MAC_CERTID not set, see https://github.com/frida/frida#macos-and-ios"
      exit 1
    fi
    ;;
  ios)
    if [ -z "$IOS_CERTID" ]; then
      echo "IOS_CERTID not set, see https://github.com/frida/frida#macos-and-ios"
      exit 1
    fi
    ;;
  *)
    echo "Unexpected host OS"
    exit 1
    ;;
esac

cp "$server_binary" "$signed_server_binary"

if [ "$strip_enabled" = "true" ]; then
  "$strip_binary" "$signed_server_binary"
fi

case $host_os in
  macos)
    "$CODESIGN" -f -s "$MAC_CERTID" -i "re.frida.Server" "$signed_server_binary" || exit 1
    ;;
  ios)
    "$CODESIGN" -f -s "$IOS_CERTID" --entitlements "$server_entitlements" "$signed_server_binary" || exit 1
    ;;
esac
