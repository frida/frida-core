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
	sleeper-qnx-arm \
	simple-agent-qnx-arm.so

sleeper-qnx-arm: sleeper-unix.c
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@.tmp
	$(STRIP) --strip-all $@.tmp
	mv $@.tmp $@

simple-agent-qnx-arm.so: simple-agent.c simple-agent-qnx-arm.version
	$(CC) $(CFLAGS) $(LDFLAGS) \
		-shared \
		-Wl,-soname,simple-agent-qnx-arm.so \
		-Wl,--version-script=simple-agent-qnx-arm.version \
		$< \
		-o $@.tmp
	$(STRIP) --strip-all $@.tmp
	mv $@.tmp $@

simple-agent-qnx-arm.version:
	echo "SIMPLE_AGENT_QNX_ARM_1.0 {"     > $@.tmp
	echo "  global:"             >> $@.tmp
	echo "    frida_agent_main;" >> $@.tmp
	echo ""                      >> $@.tmp
	echo "  local:"              >> $@.tmp
	echo "    *;"                >> $@.tmp
	echo "};"                    >> $@.tmp
	mv $@.tmp $@

.PHONY: all
