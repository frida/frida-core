#!/bin/bash

input_path="$1"
output_path="$2"
identity="$3"
host_os="$4"
strip_binary="$5"
strip_enabled="$6"

case $host_os in
  macos|ios)
    if [ -z "$INSTALL_NAME_TOOL" ]; then
      echo "INSTALL_NAME_TOOL not set"
      exit 1
    fi
    if [ -z "$CODESIGN" ]; then
      echo "CODESIGN not set"
      exit 1
    fi
    ;;
esac
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
esac

intermediate_path=$output_path.tmp
cp -a "$input_path" "$intermediate_path"

if [ "$strip_enabled" = "true" ]; then
  "$strip_binary" "$intermediate_path" || exit 1
fi

case $host_os in
  macos|ios)
    "$INSTALL_NAME_TOOL" -id "$identity" "$intermediate_path" || exit 1

    case $host_os in
      macos)
        "$CODESIGN" -f -s "$MACOS_CERTID" "$intermediate_path" || exit 1
        ;;
      ios)
        "$CODESIGN" -f -s "$IOS_CERTID" "$intermediate_path" || exit 1
        ;;
    esac
    ;;
esac

mv "$intermediate_path" "$output_path"
