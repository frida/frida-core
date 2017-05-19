#!/bin/bash

host_os="$1"
agent32="$2"
agent64="$3"
output_dir="$4"
resource_compiler="$5"
resource_config="$6"
strip_binary="$7"
strip_enabled="$8"

priv_dir="$output_dir/frida-agent@emb"

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
    embedded_agent="$priv_dir/frida-agent.dylib"

    if [ -f "$agent32" -a -f "$agent64" ]; then
      "$LIPO" "$agent32" "$agent64" -create -output "$embedded_agent" || exit 1
    elif [ -f "$agent32" ]; then
      cp "$agent32" "$embedded_agent" || exit 1
    elif [ -f "$agent64" ]; then
      cp "$agent64" "$embedded_agent" || exit 1
    else
      echo "At least one agent must be provided"
      exit 1
    fi

    if [ "$strip_enabled" = "true" ]; then
      "$strip_binary" "$embedded_agent" || exit 1
    fi

    case $host_os in
      macos)
        "$CODESIGN" -f -s "$MAC_CERTID" "$embedded_agent" || exit 1
        ;;
      ios)
        "$CODESIGN" -f -s "$IOS_CERTID" "$embedded_agent" || exit 1
        ;;
    esac

    exec "$resource_compiler" --toolchain=apple -c "$resource_config" -o "$output_dir/frida-data-agent" "$embedded_agent"
    ;;
  *)
    embedded_agents=()

    embedded_agent="$priv_dir/frida-agent-32.so"
    if [ -f "$agent32" ]; then
      cp "$agent32" "$embedded_agent" || exit 1

      if [ "$strip_enabled" = "true" ]; then
        "$strip_binary" "$embedded_agent" || exit 1
      fi
    else
      touch "$embedded_agent"
    fi
    embedded_agents+=("$embedded_agent")

    embedded_agent="$priv_dir/frida-agent-64.so"
    if [ -f "$agent64" ]; then

      cp "$agent64" "$embedded_agent" || exit 1

      if [ "$strip_enabled" = "true" ]; then
        "$strip_binary" "$embedded_agent" || exit 1
      fi
    else
      touch "$embedded_agent"
    fi
    embedded_agents+=("$embedded_agent")

    exec "$resource_compiler" --toolchain=gnu -c "$resource_config" -o "$output_dir/frida-data-agent" "${embedded_agents[@]}"
    ;;
esac
