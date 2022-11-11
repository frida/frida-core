#!/usr/bin/env bash

input_server_path=$1
input_entitlements_path=$2
output_server_path=$3
host_os=$4
strip_command=()
if [ "$5" = ">>>" ]; then
  shift 5
  while true; do
    cur=$1
    shift 1
    if [ "$cur" = "<<<" ]; then
      break
    fi
    strip_command+=("$cur")
  done
else
  echo "Invalid argument" > /dev/stderr
  exit 1
fi
strip_enabled=$1
codesign=$2

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

intermediate_path=$output_server_path.tmp
rm -f "$intermediate_path"
cp -a "$input_server_path" "$intermediate_path"

if [ "$strip_enabled" = "true" ]; then
  "${strip_command[@]}" "$intermediate_path" || exit 1
fi

case $host_os in
  macos|ios)
    case $host_os in
      macos)
        "$codesign" -f -s "$MACOS_CERTID" -i "re.frida.Server" "$intermediate_path" || exit 1
        ;;
      ios)
        "$codesign" -f -s "$IOS_CERTID" --entitlements "$input_entitlements_path" "$intermediate_path" || exit 1
        ;;
    esac
    ;;
esac

mv "$intermediate_path" "$output_server_path"
