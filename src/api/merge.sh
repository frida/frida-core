#!/usr/bin/env bash

ar_binary="$1"
libtool_binary="$2"
build_dir="$3"
output_lib="$4"
shift 4

if [ ! -e "$ar_binary" ]; then
  echo "Error: ar_binary not found"
  exit 1
fi

if [ ! -e "$libtool_binary" ]; then
  echo "Error: libtool_binary not found"
  exit 1
fi

if [ -n "$libtool_binary" ]; then
  exec "$libtool_binary" -static -o "$output_lib" "$@"
else
  priv_dir="$build_dir/frida-core-library@mrg"
  mri_script="$priv_dir/merge.mri"

  mkdir -p "$priv_dir"

  echo "create $output_lib" > "$mri_script"
  while [[ $# > 0 ]]; do
    ext=${1##*.}
    if [[ "$ext" == 'a' ]]; then
      echo "addlib $1" >> "$mri_script"
    else
      # $1 is *.o or *.so
      echo "addmod $1" >> "$mri_script"
    fi
    shift
  done
  echo "save" >> "$mri_script"
  echo "end" >> "$mri_script"

  exec "$ar_binary" -M < "$mri_script"
  if [ $? -ne 0 ]; then
    echo "Error creating $output_lib"
    exit 1
  fi
fi