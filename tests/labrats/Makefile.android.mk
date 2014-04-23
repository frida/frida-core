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
	unixvictim-android-arm \
	unixattacker-android-arm.so

unixvictim-android-arm: unixvictim.c
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@.tmp
	$(STRIP) --strip-all $@.tmp
	mv $@.tmp $@

unixattacker-android-arm.so: unixattacker.c
	$(CC) $(CFLAGS) $(LDFLAGS) -shared $< -o $@.tmp
	$(STRIP) --strip-all $@.tmp
	mv $@.tmp $@

.PHONY: all
