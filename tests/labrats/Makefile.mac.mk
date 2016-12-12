MACOS_MINVER = 10.9
MACOS_SDKVER = 10.12
MACOS_CC := $(shell xcrun --sdk macosx$(MACOS_SDKVER) -f clang)
MACOS_CFLAGS := -Wall -pipe -Os -isysroot $(shell xcrun --sdk macosx$(MACOS_SDKVER) --show-sdk-path) -mmacosx-version-min=$(MACOS_MINVER)
MACOS_LDFLAGS := -Wl,-dead_strip

IOS_MINVER = 7.0
IOS_SDKVER = 10.1
IOS_CC := $(shell xcrun --sdk iphoneos$(IOS_SDKVER) -f clang)
IOS_CFLAGS := -Wall -pipe -Os -isysroot $(shell xcrun --sdk iphoneos$(IOS_SDKVER) --show-sdk-path) -miphoneos-version-min=$(IOS_MINVER)
IOS_LDFLAGS := -Wl,-dead_strip

all: \
	sleeper-macos \
	sleeper-ios \
	simple-agent-macos.dylib \
	simple-agent-ios.dylib \
	resident-agent-macos.dylib \
	resident-agent-ios.dylib \
	stdio-writer-macos \
	stdio-writer-ios

sleeper-macos: sleeper-unix.c
	$(MACOS_CC) $(MACOS_CFLAGS) $(MACOS_LDFLAGS) -m32 $< -o $@.32
	$(MACOS_CC) $(MACOS_CFLAGS) $(MACOS_LDFLAGS) -m64 $< -o $@.64
	strip -Sx $@.32 $@.64
	lipo $@.32 $@.64 -create -output $@
	$(RM) $@.32 $@.64

sleeper-ios: sleeper-unix.c sleeper.xcent
	$(IOS_CC) $(IOS_CFLAGS) $(IOS_LDFLAGS) -arch armv7 $< -o $@.armv7
	$(IOS_CC) $(IOS_CFLAGS) $(IOS_LDFLAGS) -arch arm64 $< -o $@.arm64
	strip -Sx $@.armv7 $@.arm64
	lipo $@.armv7 $@.arm64 -create -output $@.unsigned
	$(RM) $@.armv7 $@.arm64
	codesign -s "$$IOS_CERTID" --entitlements sleeper.xcent $@.unsigned
	mv $@.unsigned $@

%-agent-macos.dylib: %-agent.c
	$(MACOS_CC) $(MACOS_CFLAGS) $(MACOS_LDFLAGS) -m32 -dynamiclib $< -o $@.32
	$(MACOS_CC) $(MACOS_CFLAGS) $(MACOS_LDFLAGS) -m64 -dynamiclib $< -o $@.64
	strip -Sx $@.32 $@.64
	lipo $@.32 $@.64 -create -output $@
	$(RM) $@.32 $@.64

%-agent-ios.dylib: %-agent.c
	$(IOS_CC) $(IOS_CFLAGS) $(IOS_LDFLAGS) -arch armv7 -dynamiclib $< -o $@.armv7
	$(IOS_CC) $(IOS_CFLAGS) $(IOS_LDFLAGS) -arch arm64 -dynamiclib $< -o $@.arm64
	strip -Sx $@.armv7 $@.arm64
	lipo $@.armv7 $@.arm64 -create -output $@
	$(RM) $@.armv7 $@.arm64

stdio-writer-macos: stdio-writer.c
	$(MACOS_CC) $(MACOS_CFLAGS) $(MACOS_LDFLAGS) -m32 $< -o $@.32
	$(MACOS_CC) $(MACOS_CFLAGS) $(MACOS_LDFLAGS) -m64 $< -o $@.64
	strip -Sx $@.32 $@.64
	lipo $@.32 $@.64 -create -output $@
	$(RM) $@.32 $@.64

stdio-writer-ios: stdio-writer.c
	$(IOS_CC) $(IOS_CFLAGS) $(IOS_LDFLAGS) -arch armv7 $< -o $@.armv7
	$(IOS_CC) $(IOS_CFLAGS) $(IOS_LDFLAGS) -arch arm64 $< -o $@.arm64
	strip -Sx $@.armv7 $@.arm64
	lipo $@.armv7 $@.arm64 -create -output $@.unsigned
	$(RM) $@.armv7 $@.arm64
	codesign -s "$$IOS_CERTID" $@.unsigned
	mv $@.unsigned $@

.PHONY: all
