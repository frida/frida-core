#!/bin/bash

ar_binary="$1"
libtool_binary="$2"
build_dir="$3"
output_lib="$4"
shift 4

if [ -n "$libtool_binary" ]; then
  exec "$libtool_binary" -static -o "$output_lib" "$@"
else
  priv_dir="$build_dir/frida-core-library@mrg"
  mri_script="$priv_dir/merge.mri"

  mkdir -p "$priv_dir"

  echo "create $output_lib" > "$mri_script"
  while [[ $# > 0 ]]; do
    echo "addlib $1" >> "$mri_script"
    shift
  done
  echo "save" >> "$mri_script"
  echo "end" >> "$mri_script"

  exec "$ar_binary" -M < "$mri_script"
fi
