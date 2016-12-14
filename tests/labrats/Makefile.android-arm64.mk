CC := $$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/bin/clang
STRIP := $$ANDROID_NDK_ROOT/toolchains/aarch64-linux-android-4.9/prebuilt/darwin-x86_64/bin/aarch64-linux-android-strip
CFLAGS := \
	--sysroot=$$ANDROID_NDK_ROOT/platforms/android-21/arch-arm64 \
	-gcc-toolchain $$ANDROID_NDK_ROOT/toolchains/aarch64-linux-android-4.9/prebuilt/darwin-x86_64 \
	-target aarch64-none-linux-android \
	-no-canonical-prefixes \
	-Wall \
	-pipe \
	-fPIC -fPIE \
	-Os \
	-fdata-sections -ffunction-sections \
	-funwind-tables -fno-exceptions -fno-rtti \
	-DANDROID \
	-I$$ANDROID_NDK_ROOT/platforms/android-21/arch-arm64/usr/include
LDFLAGS := \
	-Wl,--no-undefined \
	-Wl,-z,noexecstack \
	-Wl,-z,relro \
	-Wl,-z,now \
	-Wl,--gc-sections

all: \
	sleeper-android-arm64 \
	simple-agent-android-arm64.so \
	resident-agent-android-arm64.so \
	$(NULL)

sleeper-android-arm64: sleeper-unix.c
	$(CC) $(CFLAGS) $(LDFLAGS) -pie $< -o $@.tmp
	$(STRIP) --strip-all $@.tmp
	mv $@.tmp $@

%-agent-android-arm64.so: %-agent.c %-agent-android-arm64.version
	$(CC) $(CFLAGS) $(LDFLAGS) \
		-shared \
		-Wl,-soname,$*-agent-android-arm64.so \
		-Wl,--version-script=$*-agent-android-arm64.version \
		$< \
		-o $@.tmp
	$(STRIP) --strip-all $@.tmp
	mv $@.tmp $@

%-agent-android-arm64.version:
	echo "LABRAT_AGENT_ANDROID_ARM64_1.0 {" > $@.tmp
	echo "  global:"             >> $@.tmp
	echo "    frida_agent_main;" >> $@.tmp
	echo ""                      >> $@.tmp
	echo "  local:"              >> $@.tmp
	echo "    *;"                >> $@.tmp
	echo "};"                    >> $@.tmp
	mv $@.tmp $@

.PHONY: all
