#!/bin/bash

host_os="$1"
helper_modern="$2"
helper_legacy="$3"
output_dir="$4"
resource_compiler="$5"
strip_binary="$6"
strip_enabled="$7"

priv_dir="$output_dir/frida-helper@emb"
embedded_helper_modern="$priv_dir/frida-helper-64"
embedded_helper_legacy="$priv_dir/frida-helper-32"
resource_config="$priv_dir/frida-helper-process.resources"

mkdir -p "$priv_dir"

if [ -f "$helper_modern" ]; then
  cp "$helper_modern" "$embedded_helper_modern" || exit 1
  if [ "$strip_enabled" = "true" ]; then
    "$strip_binary" "$embedded_helper_modern" || exit 1
  fi
else
  touch "$embedded_helper_modern"
fi

if [ -f "$helper_legacy" ]; then
  cp "$helper_legacy" "$embedded_helper_legacy" || exit 1
  if [ "$strip_enabled" = "true" ]; then
    "$strip_binary" "$embedded_helper_legacy" || exit 1
  fi
else
  touch "$embedded_helper_legacy"
fi

cat > "$resource_config" << EOF
[resource-compiler]
namespace = Frida.Data.Helper
EOF

exec "$resource_compiler" --toolchain=gnu -c "$resource_config" -o "$output_dir/frida-data-helper-process" "$embedded_helper_modern" "$embedded_helper_legacy"
