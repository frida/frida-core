MAC_MINVER = 10.7
MAC_SDKVER = 10.9
MAC_CC := $(shell xcrun --sdk macosx$(MAC_SDKVER) -f clang)
MAC_CFLAGS := -isysroot $(shell xcrun --sdk macosx$(MAC_SDKVER) --show-sdk-path) -mmacosx-version-min=$(MAC_MINVER)
MAC_LDFLAGS := -Wl,-dead_strip

IOS_MINVER = 7.0
IOS_SDKVER = 7.1
IOS_CC := $(shell xcrun --sdk iphoneos$(IOS_SDKVER) -f clang)
IOS_CFLAGS := -isysroot $(shell xcrun --sdk iphoneos$(IOS_SDKVER) --show-sdk-path) -miphoneos-version-min=$(IOS_MINVER)
IOS_LDFLAGS := -Wl,-dead_strip

all: \
	unixvictim-mac \
	unixvictim-ios \
	unixattacker-mac.dylib \
	unixattacker-ios.dylib

unixvictim-mac: unixvictim.c
	$(MAC_CC) $(MAC_CFLAGS) $(MAC_LDFLAGS) -m32 $< -o $@.32
	$(MAC_CC) $(MAC_CFLAGS) $(MAC_LDFLAGS) -m64 $< -o $@.64
	strip -Sx $@.32 $@.64
	lipo $@.32 $@.64 -create -output $@
	$(RM) $@.32 $@.64

unixvictim-ios: unixvictim.c unixvictim.xcent
	$(IOS_CC) $(IOS_CFLAGS) $(IOS_LDFLAGS) -arch armv7 $< -o $@.armv7
	$(IOS_CC) $(IOS_CFLAGS) $(IOS_LDFLAGS) -arch arm64 $< -o $@.arm64
	strip -Sx $@.armv7 $@.arm64
	lipo $@.armv7 $@.arm64 -create -output $@.unsigned
	$(RM) $@.armv7 $@.arm64
	codesign -s "$$IOS_CERTID" --entitlements unixvictim.xcent $@.unsigned
	mv $@.unsigned $@

unixattacker-mac.dylib: unixattacker.c
	$(MAC_CC) $(MAC_CFLAGS) $(MAC_LDFLAGS) -m32 -dynamiclib $< -o $@.32
	$(MAC_CC) $(MAC_CFLAGS) $(MAC_LDFLAGS) -m64 -dynamiclib $< -o $@.64
	strip -Sx $@.32 $@.64
	lipo $@.32 $@.64 -create -output $@
	$(RM) $@.32 $@.64

unixattacker-ios.dylib: unixattacker.c
	$(IOS_CC) $(IOS_CFLAGS) $(IOS_LDFLAGS) -arch armv7 -dynamiclib $< -o $@.armv7
	$(IOS_CC) $(IOS_CFLAGS) $(IOS_LDFLAGS) -arch arm64 -dynamiclib $< -o $@.arm64
	strip -Sx $@.armv7 $@.arm64
	lipo $@.armv7 $@.arm64 -create -output $@
	$(RM) $@.armv7 $@.arm64

.PHONY: all
