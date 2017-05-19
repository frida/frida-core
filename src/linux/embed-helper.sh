#!/bin/bash

host_os="$1"
helper32="$2"
helper64="$3"
output_dir="$4"
resource_compiler="$5"
strip_binary="$6"
strip_enabled="$7"

priv_dir="$output_dir/frida-helper@emb"
embedded_helper32="$priv_dir/frida-helper-32"
embedded_helper64="$priv_dir/frida-helper-64"
resource_config="$priv_dir/frida-helper-process.resources"

mkdir -p "$priv_dir"

if [ -f "$helper32" ]; then
  cp "$helper32" "$embedded_helper32" || exit 1
  if [ "$strip_enabled" = "true" ]; then
    "$strip_binary" "$embedded_helper32" || exit 1
  fi
else
  touch "$embedded_helper32"
fi

if [ -f "$helper64" ]; then
  cp "$helper64" "$embedded_helper64" || exit 1
  if [ "$strip_enabled" = "true" ]; then
    "$strip_binary" "$embedded_helper64" || exit 1
  fi
else
  touch "$embedded_helper64"
fi

cat > "$resource_config" << EOF
[resource-compiler]
namespace = Frida.Data.Helper
EOF

exec "$resource_compiler" --toolchain=gnu -c "$resource_config" -o "$output_dir/frida-data-helper-process" "$embedded_helper32" "$embedded_helper64"
