#!/bin/bash

host_os="$1"
loader32="$2"
loader64="$3"
output_dir="$4"
resource_compiler="$5"
resource_config="$6"
strip_binary="$7"
strip_enabled="$8"

priv_dir="$output_dir/frida-loader@emb"

case $host_os in
  macos|ios)
    if [ -z "$LIPO" ]; then
      echo "LIPO not set"
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
esac

mkdir -p "$priv_dir"

case $host_os in
  macos|ios)
    embedded_loader="$priv_dir/FridaLoader.dylib"

    if [ -f "$loader32" -a -f "$loader64" ]; then
      "$LIPO" "$loader32" "$loader64" -create -output "$embedded_loader" || exit 1
    elif [ -f "$loader32" ]; then
      cp "$loader32" "$embedded_loader" || exit 1
    elif [ -f "$loader64" ]; then
      cp "$loader64" "$embedded_loader" || exit 1
    else
      echo "At least one loader must be provided"
      exit 1
    fi

    if [ "$strip_enabled" = "true" ]; then
      "$strip_binary" "$embedded_loader" || exit 1
    fi

    case $host_os in
      macos)
        "$CODESIGN" -f -s "$MAC_CERTID" "$embedded_loader" || exit 1
        ;;
      ios)
        "$CODESIGN" -f -s "$IOS_CERTID" "$embedded_loader" || exit 1
        ;;
    esac

    exec "$resource_compiler" --toolchain=apple -c "$resource_config" -o "$output_dir/frida-data-loader" "$embedded_loader"
    ;;
  *)
    embedded_loaders=()

    embedded_loader="$priv_dir/frida-loader-32.so"
    if [ -f "$loader32" ]; then
      cp "$loader32" "$embedded_loader" || exit 1

      if [ "$strip_enabled" = "true" ]; then
        "$strip_binary" "$embedded_loader" || exit 1
      fi
    else
      touch "$embedded_loader"
    fi
    embedded_loaders+=("$embedded_loader")

    embedded_loader="$priv_dir/frida-loader-64.so"
    if [ -f "$loader64" ]; then

      cp "$loader64" "$embedded_loader" || exit 1

      if [ "$strip_enabled" = "true" ]; then
        "$strip_binary" "$embedded_loader" || exit 1
      fi
    else
      touch "$embedded_loader"
    fi
    embedded_loaders+=("$embedded_loader")

    exec "$resource_compiler" --toolchain=gnu -c "$resource_config" -o "$output_dir/frida-data-loader" "${embedded_loaders[@]}"
    ;;
esac
