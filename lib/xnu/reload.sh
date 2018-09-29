#!/bin/sh

KEXT_NAME=FridaKernelAgent.kext

# Unload and remove old kext (does nothing on first build)
sudo kextunload "/Library/Extensions/$KEXT_NAME" &>/dev/null
sudo rm -rf "/Library/Extensions/$KEXT_NAME"

# Set up temp dir and cleanup trap
BUILD_DIR="$(mktemp -d)"

cleanup () {
  rm -rf "$BUILD_DIR"
}
trap cleanup EXIT

# cd to sources
cd "$(dirname "$0")"

xcodebuild build \
  CONFIGURATION_BUILD_DIR="$BUILD_DIR" \
  CODE_SIGN_IDENTITY="$CODE_SIGN_IDENTITY" \
  &>/dev/null

if [ $? -ne 0 ]; then
  echo "Failed to build kext" >&2
  exit 1
fi

# Move, fix permissions, and load
sudo mv "$BUILD_DIR/$KEXT_NAME" "/Library/Extensions/$KEXT_NAME"
sudo chown -R root:wheel "/Library/Extensions/$KEXT_NAME"
sudo kextload "/Library/Extensions/$KEXT_NAME"
