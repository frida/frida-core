#!/usr/bin/env bash

agent_modern=$1
agent_legacy=$2
agent_emulated_modern=$3
agent_emulated_legacy=$4
output_dir=$5
host_os=$6
resource_compiler=$7
resource_config=$8
lipo=$9

priv_dir="$output_dir/frida-agent@emb"

mkdir -p "$priv_dir"

collect_generic_agent ()
{
  embedded_agent="$priv_dir/frida-agent-$2.so"
  if [ -f "$1" ]; then
    cp "$1" "$embedded_agent" || exit 1
  else
    touch "$embedded_agent"
  fi
  embedded_agents+=("$embedded_agent")
}

case $host_os in
  macos|ios|watchos|tvos)
    embedded_agent="$priv_dir/frida-agent.dylib"

    if [ -f "$agent_modern" -a -f "$agent_legacy" ]; then
      "$lipo" "$agent_modern" "$agent_legacy" -create -output "$embedded_agent" || exit 1
    elif [ -f "$agent_modern" ]; then
      cp "$agent_modern" "$embedded_agent" || exit 1
    elif [ -f "$agent_legacy" ]; then
      cp "$agent_legacy" "$embedded_agent" || exit 1
    else
      echo "At least one agent must be provided"
      exit 1
    fi

    exec "$resource_compiler" --toolchain=apple -c "$resource_config" -o "$output_dir/frida-data-agent" "$embedded_agent"
    ;;
  freebsd|qnx)
    embedded_agent="$priv_dir/frida-agent.so"

    if [ -f "$agent_modern" ]; then
      cp "$agent_modern" "$embedded_agent" || exit 1
    elif [ -f "$agent_legacy" ]; then
      cp "$agent_legacy" "$embedded_agent" || exit 1
    else
      echo "An agent must be provided"
      exit 1
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
