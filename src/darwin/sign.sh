#!/bin/sh

identity="$1"
host_os="$2"
binary="$3"
entitlements="$4"
signed_binary="$5"

if [ -z "$CODESIGN" ]; then
  echo "CODESIGN not set"
  exit 1
fi

case $host_os in
  macos)
    if [ -z "$MACOS_CERTID" ]; then
      echo "MACOS_CERTID not set, see https://github.com/frida/frida#macos-and-ios"
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

cp "$binary" "$signed_binary"

case $host_os in
  macos)
    "$CODESIGN" -f -s "$MACOS_CERTID" -i "$identity" "$signed_binary" || exit 1
    ;;
  ios)
    "$CODESIGN" -f -s "$IOS_CERTID" --entitlements "$entitlements" "$signed_binary" || exit 1
    ;;
esac
