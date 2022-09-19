#!/usr/bin/env bash

host_os=$1
strip_binary=$2
strip_enabled=$3
install_name_tool=$4
codesign=$5
input_path=$6
output_path=$7
identity=$8

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
rm -f "$intermediate_path"
cp -a "$input_path" "$intermediate_path"

if [ "$strip_enabled" = "true" ]; then
  "$strip_binary" "$intermediate_path" || exit 1
fi

case $host_os in
  macos|ios)
    "$install_name_tool" -id "$identity" "$intermediate_path" || exit 1

    case $host_os in
      macos)
        "$codesign" -f -s "$MACOS_CERTID" "$intermediate_path" || exit 1
        ;;
      ios)
        "$codesign" -f -s "$IOS_CERTID" "$intermediate_path" || exit 1
        ;;
    esac
    ;;
esac

mv "$intermediate_path" "$output_path"
