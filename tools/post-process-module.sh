#!/usr/bin/env bash

host_os=$1
strip_command=()
if [ "$2" = ">>>" ]; then
  shift 2
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
install_name_tool=$2
codesign=$3
input_path=$4
output_path=$5
identity=$6

case $host_os in
  macos)
    if [ -z "$MACOS_CERTID" ]; then
      echo "MACOS_CERTID not set, see https://github.com/frida/frida#apple-oses"
      exit 1
    fi
    ;;
  ios)
    if [ -z "$IOS_CERTID" ]; then
      echo "IOS_CERTID not set, see https://github.com/frida/frida#apple-oses"
      exit 1
    fi
    ;;
  watchos)
    if [ -z "$WATCHOS_CERTID" ]; then
      echo "WATCHOS_CERTID not set, see https://github.com/frida/frida#apple-oses"
      exit 1
    fi
    ;;
  tvos)
    if [ -z "$TVOS_CERTID" ]; then
      echo "TVOS_CERTID not set, see https://github.com/frida/frida#apple-oses"
      exit 1
    fi
    ;;
esac

intermediate_path=$output_path.tmp
rm -f "$intermediate_path"
cp -a "$input_path" "$intermediate_path"

if [ "$strip_enabled" = "true" ]; then
  "${strip_command[@]}" "$intermediate_path" || exit 1
fi

case $host_os in
  macos|ios|watchos|tvos)
    "$install_name_tool" -id "$identity" "$intermediate_path" || exit 1

    case $host_os in
      macos)
        "$codesign" -f -s "$MACOS_CERTID" "$intermediate_path" || exit 1
        ;;
      ios)
        "$codesign" -f -s "$IOS_CERTID" "$intermediate_path" || exit 1
        ;;
      watchos)
        "$codesign" -f -s "$WATCHOS_CERTID" "$intermediate_path" || exit 1
        ;;
      tvos)
        "$codesign" -f -s "$TVOS_CERTID" "$intermediate_path" || exit 1
        ;;
    esac
    ;;
esac

mv "$intermediate_path" "$output_path"
