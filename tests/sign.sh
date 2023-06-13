#!/bin/sh

host_os=$1
codesign=$2
runner_binary=$3
runner_entitlements=$4
signed_runner_binary=$5

case $host_os in
  macos)
    if [ -z "$MACOS_CERTID" ]; then
      echo "MACOS_CERTID not set, see https://github.com/frida/frida#apple-oses"
      exit 1
    fi
    ;;
  ios)
    if [ -z "$IOS_CERTID" ]; then
      echo "IOS_CERTID not set, see https://github.com/frida/frida#apple-oses"
      exit 1
    fi
    ;;
  tvos)
    if [ -z "$TVOS_CERTID" ]; then
      echo "TVOS_CERTID not set, see https://github.com/frida/frida#apple-oses"
      exit 1
    fi
    ;;
  *)
    echo "Unexpected host OS"
    exit 1
    ;;
esac

rm -f "$signed_runner_binary"
cp "$runner_binary" "$signed_runner_binary"

case $host_os in
  macos)
    "$codesign" -f -s "$MACOS_CERTID" -i "re.frida.CoreTests" "$signed_runner_binary" || exit 1
    ;;
  ios)
    "$codesign" -f -s "$IOS_CERTID" --entitlements "$runner_entitlements" "$signed_runner_binary" || exit 1
    ;;
  tvos)
    "$codesign" -f -s "$TVOS_CERTID" --entitlements "$runner_entitlements" "$signed_runner_binary" || exit 1
    ;;
esac
