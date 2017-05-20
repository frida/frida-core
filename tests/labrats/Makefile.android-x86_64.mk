CC := $$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/bin/clang
STRIP := $$ANDROID_NDK_ROOT/toolchains/x86_64-4.9/prebuilt/darwin-x86_64/bin/x86_64-linux-android-strip
CFLAGS := \
	--sysroot=$$ANDROID_NDK_ROOT/platforms/android-21/arch-x86_64 \
	-gcc-toolchain $$ANDROID_NDK_ROOT/toolchains/x86_64-4.9/prebuilt/darwin-x86_64 \
	-target x86_64-none-linux-android \
	-no-canonical-prefixes \
	-Wall \
	-pipe \
	-fPIC -fPIE \
	-Os \
	-fdata-sections -ffunction-sections \
	-funwind-tables -fno-exceptions -fno-rtti \
	-DANDROID \
	-I$$ANDROID_NDK_ROOT/platforms/android-21/arch-x86_64/usr/include
LDFLAGS := \
	-Wl,--no-undefined \
	-Wl,-z,noexecstack \
	-Wl,-z,relro \
	-Wl,-z,now \
	-Wl,--gc-sections

all: \
	sleeper-android-x86_64 \
	simple-agent-android-x86_64.so \
	resident-agent-android-x86_64.so \
	$(NULL)

sleeper-android-x86_64: sleeper-unix.c
	$(CC) $(CFLAGS) $(LDFLAGS) -pie $< -o $@.tmp
	$(STRIP) --strip-all $@.tmp
	mv $@.tmp $@

%-agent-android-x86_64.so: %-agent.c %-agent-android-x86_64.version
	$(CC) $(CFLAGS) $(LDFLAGS) \
		-shared \
		-Wl,-soname,$*-agent-android-x86_64.so \
		-Wl,--version-script=$*-agent-android-x86_64.version \
		$< \
		-o $@.tmp
	$(STRIP) --strip-all $@.tmp
	mv $@.tmp $@

%-agent-android-x86_64.version:
	echo "LABRAT_AGENT_ANDROID_X86_64_1.0 {" > $@.tmp
	echo "  global:"             >> $@.tmp
	echo "    frida_agent_main;" >> $@.tmp
	echo ""                      >> $@.tmp
	echo "  local:"              >> $@.tmp
	echo "    *;"                >> $@.tmp
	echo "};"                    >> $@.tmp
	mv $@.tmp $@

.PHONY: all
