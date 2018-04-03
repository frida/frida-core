CC := gcc
CFLAGS := -Wall -pipe -Os -fPIC -fdata-sections -ffunction-sections
LDFLAGS := -Wl,--gc-sections

all: \
	sleeper-linux-arm \
	sleeper-linux-armhf \
	sleeper-linux-x86 \
	sleeper-linux-x86_64 \
	forker-linux-x86 \
	forker-linux-x86_64 \
	simple-agent-linux-arm.so \
	simple-agent-linux-armhf.so \
	simple-agent-linux-x86.so \
	simple-agent-linux-x86_64.so \
	resident-agent-linux-arm.so \
	resident-agent-linux-armhf.so \
	resident-agent-linux-x86.so \
	resident-agent-linux-x86_64.so \
	$(NULL)

sleeper-linux-arm: sleeper-unix.c
	arm-linux-gnueabi-gcc $(CFLAGS) $(LDFLAGS) $< -o $@.tmp
	arm-linux-gnueabi-strip --strip-all $@.tmp
	mv $@.tmp $@

sleeper-linux-armhf: sleeper-unix.c
	arm-linux-gnueabihf-gcc $(CFLAGS) $(LDFLAGS) $< -o $@.tmp
	arm-linux-gnueabihf-strip --strip-all $@.tmp
	mv $@.tmp $@

sleeper-linux-x86: sleeper-unix.c
	$(CC) $(CFLAGS) $(LDFLAGS) -m32 $< -o $@.tmp
	strip --strip-all $@.tmp
	mv $@.tmp $@

sleeper-linux-x86_64: sleeper-unix.c
	$(CC) $(CFLAGS) $(LDFLAGS) -m64 $< -o $@.tmp
	strip --strip-all $@.tmp
	mv $@.tmp $@

sleeper-linux-mips: sleeper-unix.c
	mips-linux-gcc $(CFLAGS) $(LDFLAGS) $< -o $@.tmp
	mips-linux-strip --strip-all $@.tmp
	mv $@.tmp $@

sleeper-linux-mipsel: sleeper-unix.c
	mipsel-linux-gcc $(CFLAGS) $(LDFLAGS) $< -o $@.tmp
	mipsel-linux-strip --strip-all $@.tmp
	mv $@.tmp $@

forker-linux-x86: forker.c
	$(CC) $(CFLAGS) $(LDFLAGS) -m32 $< -o $@.tmp
	strip --strip-all $@.tmp
	mv $@.tmp $@

forker-linux-x86_64: forker.c
	$(CC) $(CFLAGS) $(LDFLAGS) -m64 $< -o $@.tmp
	strip --strip-all $@.tmp
	mv $@.tmp $@

%-agent-linux-arm.so: %-agent.c
	arm-linux-gnueabi-gcc $(CFLAGS) $(LDFLAGS) -shared $< -o $@.tmp
	arm-linux-gnueabi-strip --strip-all $@.tmp
	mv $@.tmp $@

%-agent-linux-armhf.so: %-agent.c
	arm-linux-gnueabihf-gcc $(CFLAGS) $(LDFLAGS) -shared $< -o $@.tmp
	arm-linux-gnueabihf-strip --strip-all $@.tmp
	mv $@.tmp $@

%-agent-linux-x86.so: %-agent.c
	$(CC) $(CFLAGS) $(LDFLAGS) -m32 -shared $< -o $@.tmp
	strip --strip-all $@.tmp
	mv $@.tmp $@

%-agent-linux-x86_64.so: %-agent.c
	$(CC) $(CFLAGS) $(LDFLAGS) -m64 -shared $< -o $@.tmp
	strip --strip-all $@.tmp
	mv $@.tmp $@

%-agent-linux-mips.so: %-agent.c
	mips-linux-gcc $(CFLAGS) $(LDFLAGS) -shared $< -o $@.tmp
	mips-linux-strip --strip-all $@.tmp
	mv $@.tmp $@

%-agent-linux-mipsel.so: %-agent.c
	mipsel-linux-gcc $(CFLAGS) $(LDFLAGS) -shared $< -o $@.tmp
	mipsel-linux-strip --strip-all $@.tmp
	mv $@.tmp $@

.PHONY: all
