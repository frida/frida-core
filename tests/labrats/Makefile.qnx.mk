CC := $$QNX_HOST/usr/bin/arm-unknown-nto-qnx6.5.0-gcc
STRIP := $$QNX_HOST/usr/bin/arm-unknown-nto-qnx6.5.0-strip
CFLAGS := \
	--sysroot=$$QNX_TARGET/armle \
	-no-canonical-prefixes \
	-Wall \
	-pipe \
	-fPIC \
	-Os \
	-march=armv6 -mfloat-abi=softfp -mfpu=vfpv3-d16 \
	-fdata-sections -ffunction-sections \
	-funwind-tables -fno-exceptions \
	-Dqnx \
	-I$$QNX_TARGET/usr/include
LDFLAGS := \
	-Wl,--fix-cortex-a8 \
	-Wl,--no-undefined \
	-Wl,-z,noexecstack \
	-Wl,-z,relro \
	-Wl,-z,now \
	-Wl,--gc-sections

all: \
	unixvictim-qnx-arm \
	unixattacker-qnx-arm.so

unixvictim-qnx-arm: unixvictim.c
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@.tmp
	$(STRIP) --strip-all $@.tmp
	mv $@.tmp $@

unixattacker-qnx-arm.so: unixattacker.c unixattacker-qnx-arm.version
	$(CC) $(CFLAGS) $(LDFLAGS) \
		-shared \
		-Wl,-soname,unixattacker-qnx-arm.so \
		-Wl,--version-script=unixattacker-qnx-arm.version \
		$< \
		-o $@.tmp
	$(STRIP) --strip-all $@.tmp
	mv $@.tmp $@

unixattacker-qnx-arm.version:
	echo "UNIXATTACKER_QNX_ARM_1.0 {"     > $@.tmp
	echo "  global:"             >> $@.tmp
	echo "    frida_agent_main;" >> $@.tmp
	echo ""                      >> $@.tmp
	echo "  local:"              >> $@.tmp
	echo "    *;"                >> $@.tmp
	echo "};"                    >> $@.tmp
	mv $@.tmp $@

.PHONY: all
