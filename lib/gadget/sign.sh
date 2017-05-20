#!/bin/sh

host_os="$1"
gadget_binary="$2"
signed_gadget_binary="$3"
strip_binary="$4"
strip_enabled="$5"

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

cp "$gadget_binary" "$signed_gadget_binary"

if [ "$strip_enabled" = "true" ]; then
  "$strip_binary" "$signed_gadget_binary"
fi

case $host_os in
  macos)
    "$CODESIGN" -f -s "$MAC_CERTID" "$signed_gadget_binary" || exit 1
    ;;
  ios)
    "$CODESIGN" -f -s "$IOS_CERTID" "$signed_gadget_binary" || exit 1
    ;;
esac
