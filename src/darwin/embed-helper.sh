#!/bin/bash

host_os="$1"
helper32="$2"
helper64="$3"
helper_entitlements="$4"
output_dir="$5"
resource_compiler="$6"
strip_binary="$7"
strip_enabled="$8"

priv_dir="$output_dir/frida-helper@emb"
embedded_helper="$priv_dir/frida-helper"
resource_config="$priv_dir/frida-helper-process.resources"

if [ -z "$LIPO" ]; then
  echo "LIPO not set"
  exit 1
fi

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

mkdir -p "$priv_dir"

if [ -f "$helper32" -a -f "$helper64" ]; then
  "$LIPO" "$helper32" "$helper64" -create -output "$embedded_helper" || exit 1
elif [ -f "$helper32" ]; then
  cp "$helper32" "$embedded_helper" || exit 1
elif [ -f "$helper64" ]; then
  cp "$helper64" "$embedded_helper" || exit 1
else
  echo "At least one helper must be provided"
  exit 1
fi

if [ "$strip_enabled" = "true" ]; then
  "$strip_binary" "$embedded_helper" || exit 1
fi

case $host_os in
  macos)
    "$CODESIGN" -f -s "$MAC_CERTID" -i "re.frida.Helper" "$embedded_helper" || exit 1
    ;;
  ios)
    "$CODESIGN" -f -s "$IOS_CERTID" --entitlements "$helper_entitlements" "$embedded_helper" || exit 1
    ;;
esac

cat > "$resource_config" << EOF
[resource-compiler]
namespace = Frida.Data.Helper
EOF

exec "$resource_compiler" --toolchain=apple -c "$resource_config" -o "$output_dir/frida-data-helper-process" "$embedded_helper"
