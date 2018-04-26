MACOS_MINVER = 10.9
MACOS_SDKVER = 10.13
MACOS_CC := $(shell xcrun --sdk macosx$(MACOS_SDKVER) -f clang)
MACOS_CFLAGS := -Wall -pipe -Os -isysroot $(shell xcrun --sdk macosx$(MACOS_SDKVER) --show-sdk-path) -mmacosx-version-min=$(MACOS_MINVER)
MACOS_LDFLAGS := -Wl,-dead_strip

IOS_MINVER = 7.0
IOS_SDKVER = 11.3
IOS_CC := $(shell xcrun --sdk iphoneos$(IOS_SDKVER) -f clang)
IOS_CFLAGS := -Wall -pipe -Os -isysroot $(shell xcrun --sdk iphoneos$(IOS_SDKVER) --show-sdk-path) -miphoneos-version-min=$(IOS_MINVER)
IOS_LDFLAGS := -Wl,-dead_strip

all: \
	sleeper-macos \
	sleeper-ios \
	stdio-writer-macos \
	stdio-writer-ios \
	forker-macos \
	forker-ios \
	spawner-macos \
	spawner-ios \
	simple-agent-macos.dylib \
	simple-agent-ios.dylib \
	resident-agent-macos.dylib \
	resident-agent-ios.dylib

define declare-executable-macos
$1-macos: $2
	$$(MACOS_CC) $$(MACOS_CFLAGS) $$(MACOS_LDFLAGS) -m32 $$< -o $$@.32
	$$(MACOS_CC) $$(MACOS_CFLAGS) $$(MACOS_LDFLAGS) -m64 $$< -o $$@.64
	strip -Sx $$@.32 $$@.64
	lipo $$@.32 $$@.64 -create -output $$@
	$(RM) $$@.32 $$@.64
endef

define declare-executable-ios
$1-ios: $2
	$$(IOS_CC) $$(IOS_CFLAGS) $$(IOS_LDFLAGS) -arch armv7 $$< -o $$@.armv7
	$$(IOS_CC) $$(IOS_CFLAGS) $$(IOS_LDFLAGS) -arch arm64 $$< -o $$@.arm64
	strip -Sx $$@.armv7 $$@.arm64
	lipo $$@.armv7 $$@.arm64 -create -output $$@.unsigned
	$(RM) $$@.armv7 $$@.arm64
	codesign -s "$$$$IOS_CERTID" $$@.unsigned
	mv $$@.unsigned $$@
endef

define declare-library-macos
$1-macos.dylib: $2
	$$(MACOS_CC) $$(MACOS_CFLAGS) $$(MACOS_LDFLAGS) -m32 -dynamiclib $$< -o $$@.32
	$$(MACOS_CC) $$(MACOS_CFLAGS) $$(MACOS_LDFLAGS) -m64 -dynamiclib $$< -o $$@.64
	strip -Sx $$@.32 $$@.64
	lipo $$@.32 $$@.64 -create -output $$@
	$(RM) $$@.32 $$@.64
endef

define declare-library-ios
$1-ios.dylib: $2
	$$(IOS_CC) $$(IOS_CFLAGS) $$(IOS_LDFLAGS) -arch armv7 -dynamiclib $$< -o $$@.armv7
	$$(IOS_CC) $$(IOS_CFLAGS) $$(IOS_LDFLAGS) -arch arm64 -dynamiclib $$< -o $$@.arm64
	strip -Sx $$@.armv7 $$@.arm64
	lipo $$@.armv7 $$@.arm64 -create -output $$@
	$(RM) $$@.armv7 $$@.arm64
endef

$(eval $(call declare-executable-macos,sleeper,sleeper-unix.c))
$(eval $(call declare-executable-ios,sleeper,sleeper-unix.c))

$(eval $(call declare-executable-macos,stdio-writer,stdio-writer.c))
$(eval $(call declare-executable-ios,stdio-writer,stdio-writer.c))

$(eval $(call declare-executable-macos,forker,forker.c))
$(eval $(call declare-executable-ios,forker,forker.c))

$(eval $(call declare-executable-macos,spawner,spawner-unix.c))
$(eval $(call declare-executable-ios,spawner,spawner-unix.c))

$(eval $(call declare-library-macos,simple-agent,simple-agent.c))
$(eval $(call declare-library-ios,simple-agent,simple-agent.c))

$(eval $(call declare-library-macos,resident-agent,resident-agent.c))
$(eval $(call declare-library-ios,resident-agent,resident-agent.c))

.PHONY: all
