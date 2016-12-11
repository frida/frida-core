CC := $$ANDROID_NDK_ROOT/toolchains/llvm-3.4/prebuilt/darwin-x86_64/bin/clang
STRIP := $$ANDROID_NDK_ROOT/toolchains/arm-linux-androideabi-4.8/prebuilt/darwin-x86_64/bin/arm-linux-androideabi-strip
CFLAGS := \
	--sysroot=$$ANDROID_NDK_ROOT/platforms/android-14/arch-arm \
	-gcc-toolchain $$ANDROID_NDK_ROOT/toolchains/arm-linux-androideabi-4.8/prebuilt/darwin-x86_64 \
	-target armv7-none-linux-androideabi \
	-no-canonical-prefixes \
	-Wall \
	-pipe \
	-fPIC \
	-Os \
	-march=armv7-a -mfloat-abi=softfp -mfpu=vfpv3-d16 -mthumb \
	-fdata-sections -ffunction-sections \
	-funwind-tables -fno-exceptions -fno-rtti \
	-DANDROID \
	-I$$ANDROID_NDK_ROOT/platforms/android-14/arch-arm/usr/include
LDFLAGS := \
	-Wl,--fix-cortex-a8 \
	-Wl,--no-undefined \
	-Wl,-z,noexecstack \
	-Wl,-z,relro \
	-Wl,-z,now \
	-Wl,--gc-sections

all: \
	sleeper-android-arm \
	simple-agent-android-arm.so

sleeper-android-arm: sleeper-unix.c
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@.tmp
	$(STRIP) --strip-all $@.tmp
	mv $@.tmp $@

simple-agent-android-arm.so: simple-agent.c simple-agent-android-arm.version
	$(CC) $(CFLAGS) $(LDFLAGS) \
		-shared \
		-Wl,-soname,simple-agent-android-arm.so \
		-Wl,--version-script=simple-agent-android-arm.version \
		$< \
		-o $@.tmp
	$(STRIP) --strip-all $@.tmp
	mv $@.tmp $@

simple-agent-android-arm.version:
	echo "SIMPLE_AGENT_ANDROID_ARM_1.0 {"     > $@.tmp
	echo "  global:"             >> $@.tmp
	echo "    frida_agent_main;" >> $@.tmp
	echo ""                      >> $@.tmp
	echo "  local:"              >> $@.tmp
	echo "    *;"                >> $@.tmp
	echo "};"                    >> $@.tmp
	mv $@.tmp $@

.PHONY: all
