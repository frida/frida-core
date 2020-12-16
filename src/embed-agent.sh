#!/bin/bash

host_os="$1"
agent_modern="$2"
agent_legacy="$3"
agent_emulated_modern="$4"
agent_emulated_legacy="$5"
output_dir="$6"
resource_compiler="$7"
resource_config="$8"
strip_binary="$9"
strip_enabled="${10}"

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

mkdir -p "$priv_dir"

collect_generic_agent ()
{
  embedded_agent="$priv_dir/frida-agent-$2.so"
  if [ -f "$1" ]; then
    cp "$1" "$embedded_agent" || exit 1

    if [ "$strip_enabled" = "true" ]; then
      if [ "$host_os-$2" = "android-arm" ]; then
        # FIXME: This isn't great.
        strip_dirname=$(dirname "$strip_binary")
        strip_basename=$(basename "$strip_binary")
        other_strip_binary="$strip_dirname/$(echo $strip_basename | sed 's,x86,arm,')"
        "$other_strip_binary" "$embedded_agent" || exit 1
      else
        "$strip_binary" "$embedded_agent" || exit 1
      fi
    fi
  else
    touch "$embedded_agent"
  fi
  embedded_agents+=("$embedded_agent")
}

case $host_os in
  macos|ios)
    embedded_agent="$priv_dir/frida-agent.dylib"

    if [ -f "$agent_modern" -a -f "$agent_legacy" ]; then
      "$LIPO" "$agent_modern" "$agent_legacy" -create -output "$embedded_agent" || exit 1
    elif [ -f "$agent_modern" ]; then
      cp "$agent_modern" "$embedded_agent" || exit 1
    elif [ -f "$agent_legacy" ]; then
      cp "$agent_legacy" "$embedded_agent" || exit 1
    else
      echo "At least one agent must be provided"
      exit 1
    fi

    if [ "$strip_enabled" = "true" ]; then
      "$strip_binary" "$embedded_agent" || exit 1
    fi

    case $host_os in
      macos)
        "$CODESIGN" -f -s "$MACOS_CERTID" "$embedded_agent" || exit 1
        ;;
      ios)
        "$CODESIGN" -f -s "$IOS_CERTID" "$embedded_agent" || exit 1
        ;;
    esac

    exec "$resource_compiler" --toolchain=apple -c "$resource_config" -o "$output_dir/frida-data-agent" "$embedded_agent"
    ;;
  qnx)
    embedded_agent="$priv_dir/frida-agent.so"

    if [ -f "$agent_modern" ]; then
      cp "$agent_modern" "$embedded_agent" || exit 1
    elif [ -f "$agent_legacy" ]; then
      cp "$agent_legacy" "$embedded_agent" || exit 1
    else
      echo "An agent must be provided"
      exit 1
    fi

    if [ "$strip_enabled" = "true" ]; then
      "$strip_binary" "$embedded_agent" || exit 1
    fi

    exec "$resource_compiler" --toolchain=gnu -c "$resource_config" -o "$output_dir/frida-data-agent" "$embedded_agent"
    ;;
  *)
    embedded_agents=()

    collect_generic_agent "$agent_modern" 64
    collect_generic_agent "$agent_legacy" 32
    collect_generic_agent "$agent_emulated_modern" arm64
    collect_generic_agent "$agent_emulated_legacy" arm

    exec "$resource_compiler" --toolchain=gnu -c "$resource_config" -o "$output_dir/frida-data-agent" "${embedded_agents[@]}"
    ;;
esac
