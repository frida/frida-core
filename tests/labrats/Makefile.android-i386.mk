CC := $$ANDROID_NDK_ROOT/toolchains/llvm-3.4/prebuilt/darwin-x86_64/bin/clang
STRIP := $$ANDROID_NDK_ROOT/toolchains/x86-4.8/prebuilt/darwin-x86_64/bin/i686-linux-android-strip
CFLAGS := \
	--sysroot=$$ANDROID_NDK_ROOT/platforms/android-14/arch-x86 \
	-gcc-toolchain $$ANDROID_NDK_ROOT/toolchains/x86-4.8/prebuilt/darwin-x86_64 \
	-target i686-none-linux-android \
	-no-canonical-prefixes \
	-Wall \
	-pipe \
	-fPIC \
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
	unixvictim-android-i386 \
	unixattacker-android-i386.so

unixvictim-android-i386: unixvictim.c
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@.tmp
	$(STRIP) --strip-all $@.tmp
	mv $@.tmp $@

unixattacker-android-i386.so: unixattacker.c unixattacker-android-i386.version
	$(CC) $(CFLAGS) $(LDFLAGS) \
		-shared \
		-Wl,-soname,unixattacker-android-i386.so \
		-Wl,--version-script=unixattacker-android-i386.version \
		$< \
		-o $@.tmp
	$(STRIP) --strip-all $@.tmp
	mv $@.tmp $@

unixattacker-android-i386.version:
	echo "UNIXATTACKER_ANDROID_I386_1.0 {"     > $@.tmp
	echo "  global:"             >> $@.tmp
	echo "    frida_agent_main;" >> $@.tmp
	echo ""                      >> $@.tmp
	echo "  local:"              >> $@.tmp
	echo "    *;"                >> $@.tmp
	echo "};"                    >> $@.tmp
	mv $@.tmp $@

.PHONY: all
