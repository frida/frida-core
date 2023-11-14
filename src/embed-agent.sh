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
agent_dbghelp_prefix=${10}
agent_symsrv_prefix=${11}

priv_dir="$output_dir/frida-agent@emb"

mkdir -p "$priv_dir"

collect_windows_agent ()
{
  embedded_agent="$priv_dir/frida-agent-$2.dll"
  embedded_dbghelp="$priv_dir/dbghelp-$2.dll"
  embedded_symsrv="$priv_dir/symsrv-$2.dll"
  if [ -f "$1" ]; then
    cp "$1" "$embedded_agent" || exit 1
    cp "$agent_dbghelp_prefix/dbghelp-$2.dll" "$embedded_dbghelp" || exit 1
    cp "$agent_symsrv_prefix/symsrv-$2.dll" "$embedded_symsrv" || exit 1
  else
    touch "$embedded_agent"
    touch "$embedded_dbghelp"
    touch "$embedded_symsrv"
  fi
  embedded_assets+=("$embedded_agent" "$embedded_dbghelp" "$embedded_symsrv")
}

collect_unix_agent ()
{
  embedded_agent="$priv_dir/frida-agent-$2.so"
  if [ -f "$1" ]; then
    cp "$1" "$embedded_agent" || exit 1
  else
    touch "$embedded_agent"
  fi
  embedded_assets+=("$embedded_agent")
}

case $host_os in
  windows)
    embedded_assets=()

    collect_windows_agent "$agent_modern" 64
    collect_windows_agent "$agent_legacy" 32

    exec "$resource_compiler" --toolchain=gnu -c "$resource_config" -o "$output_dir/frida-data-agent" "${embedded_assets[@]}"
    ;;
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
    embedded_assets=()

    collect_unix_agent "$agent_modern" 64
    collect_unix_agent "$agent_legacy" 32
    collect_unix_agent "$agent_emulated_modern" arm64
    collect_unix_agent "$agent_emulated_legacy" arm

    exec "$resource_compiler" --toolchain=gnu -c "$resource_config" -o "$output_dir/frida-data-agent" "${embedded_assets[@]}"
    ;;
esac
