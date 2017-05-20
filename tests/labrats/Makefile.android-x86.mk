CC := $$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/bin/clang
STRIP := $$ANDROID_NDK_ROOT/toolchains/x86-4.9/prebuilt/darwin-x86_64/bin/i686-linux-android-strip
CFLAGS := \
	--sysroot=$$ANDROID_NDK_ROOT/platforms/android-14/arch-x86 \
	-gcc-toolchain $$ANDROID_NDK_ROOT/toolchains/x86-4.9/prebuilt/darwin-x86_64 \
	-target i686-none-linux-android \
	-no-canonical-prefixes \
	-Wall \
	-pipe \
	-fPIC -fPIE \
	-Os \
	-march=i686 \
	-fdata-sections -ffunction-sections \
	-funwind-tables -fno-exceptions -fno-rtti \
	-DANDROID \
	-I$$ANDROID_NDK_ROOT/platforms/android-14/arch-x86/usr/include
LDFLAGS := \
	-Wl,--no-undefined \
	-Wl,-z,noexecstack \
	-Wl,-z,relro \
	-Wl,-z,now \
	-Wl,--gc-sections

all: \
	sleeper-android-i386 \
	simple-agent-android-i386.so \
	resident-agent-android-i386.so \
	$(NULL)

sleeper-android-i386: sleeper-unix.c
	$(CC) $(CFLAGS) $(LDFLAGS) -pie $< -o $@.tmp
	$(STRIP) --strip-all $@.tmp
	mv $@.tmp $@

%-agent-android-i386.so: %-agent.c %-agent-android-i386.version
	$(CC) $(CFLAGS) $(LDFLAGS) \
		-shared \
		-Wl,-soname,$*-agent-android-i386.so \
		-Wl,--version-script=$*-agent-android-i386.version \
		$< \
		-o $@.tmp
	$(STRIP) --strip-all $@.tmp
	mv $@.tmp $@

%-agent-android-i386.version:
	echo "LABRAT_AGENT_ANDROID_I386_1.0 {"  > $@.tmp
	echo "  global:"                       >> $@.tmp
	echo "    frida_agent_main;"           >> $@.tmp
	echo ""                                >> $@.tmp
	echo "  local:"                        >> $@.tmp
	echo "    *;"                          >> $@.tmp
	echo "};"                              >> $@.tmp
	mv $@.tmp $@

.PHONY: all
