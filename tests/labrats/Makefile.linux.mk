CC := gcc
CFLAGS := -Wall -pipe -Os -fPIC -fdata-sections -ffunction-sections
LDFLAGS := -Wl,--gc-sections

all: \
	sleeper-linux-x86 \
	sleeper-linux-x86_64 \
	sleeper-linux-arm \
	sleeper-linux-armhf \
	sleeper-linux-arm64 \
	sleeper-linux-mips \
	sleeper-linux-mipsel \
	sleeper-linux-mips64 \
	sleeper-linux-mips64el \
	forker-linux-x86 \
	forker-linux-x86_64 \
	forker-linux-arm \
	forker-linux-armhf \
	forker-linux-arm64 \
	forker-linux-mips \
	forker-linux-mipsel \
	forker-linux-mips64 \
	forker-linux-mips64el \
	spawner-linux-x86 \
	spawner-linux-x86_64 \
	spawner-linux-arm \
	spawner-linux-armhf \
	spawner-linux-arm64 \
	spawner-linux-mips \
	spawner-linux-mipsel \
	spawner-linux-mips64 \
	spawner-linux-mips64el \
	simple-agent-linux-x86.so \
	simple-agent-linux-x86_64.so \
	simple-agent-linux-arm.so \
	simple-agent-linux-armhf.so \
	simple-agent-linux-arm64.so \
	simple-agent-linux-mips.so \
	simple-agent-linux-mipsel.so \
	simple-agent-linux-mips64.so \
	simple-agent-linux-mips64el.so \
	resident-agent-linux-x86.so \
	resident-agent-linux-x86_64.so \
	resident-agent-linux-arm.so \
	resident-agent-linux-armhf.so \
	resident-agent-linux-arm64.so \
	resident-agent-linux-mips.so \
	resident-agent-linux-mipsel.so \
	resident-agent-linux-mips64.so \
	resident-agent-linux-mips64el.so \
	$(NULL)

define declare-executable
$1-linux-x86: $2
	$$(CC) $$(CFLAGS) $$(LDFLAGS) -m32 $$< -o $$@.tmp $3
	strip --strip-all $$@.tmp
	mv $$@.tmp $$@

$1-linux-x86_64: $2
	$$(CC) $$(CFLAGS) $$(LDFLAGS) -m64 $$< -o $$@.tmp $3
	strip --strip-all $$@.tmp
	mv $$@.tmp $$@

$1-linux-arm: $2
	arm-linux-gnueabi-gcc $$(CFLAGS) $$(LDFLAGS) $$< -o $$@.tmp $3
	arm-linux-gnueabi-strip --strip-all $$@.tmp
	mv $$@.tmp $$@

$1-linux-armhf: $2
	arm-linux-gnueabihf-gcc $$(CFLAGS) $$(LDFLAGS) $$< -o $$@.tmp $3
	arm-linux-gnueabihf-strip --strip-all $$@.tmp
	mv $$@.tmp $$@

$1-linux-arm64: $2
	aarch64-linux-gnu-gcc $$(CFLAGS) $$(LDFLAGS) $$< -o $$@.tmp $3
	aarch64-linux-gnu-strip --strip-all $$@.tmp
	mv $$@.tmp $$@

$1-linux-mips: $2
	mips-linux-gnu-gcc $$(CFLAGS) $$(LDFLAGS) $$< -o $$@.tmp $3
	mips-linux-gnu-strip --strip-all $$@.tmp
	mv $$@.tmp $$@

$1-linux-mipsel: $2
	mipsel-linux-gnu-gcc $$(CFLAGS) $$(LDFLAGS) $$< -o $$@.tmp $3
	mipsel-linux-gnu-strip --strip-all $$@.tmp
	mv $$@.tmp $$@

$1-linux-mips64: $2
	mips64-linux-gnuabi64-gcc $$(CFLAGS) $$(LDFLAGS) $$< -o $$@.tmp $3
	mips64-linux-gnuabi64-strip --strip-all $$@.tmp
	mv $$@.tmp $$@

$1-linux-mips64el: $2
	mips64el-linux-gnuabi64-gcc $$(CFLAGS) $$(LDFLAGS) $$< -o $$@.tmp $3
	mips64el-linux-gnuabi64-strip --strip-all $$@.tmp
	mv $$@.tmp $$@
endef

$(eval $(call declare-executable,sleeper,sleeper-unix.c))

$(eval $(call declare-executable,forker,forker.c))

$(eval $(call declare-executable,spawner,spawner-unix.c,-ldl))

%-agent-linux-x86.so: %-agent.c
	$(CC) $(CFLAGS) $(LDFLAGS) -m32 -shared $< -o $@.tmp
	strip --strip-all $@.tmp
	mv $@.tmp $@

%-agent-linux-x86_64.so: %-agent.c
	$(CC) $(CFLAGS) $(LDFLAGS) -m64 -shared $< -o $@.tmp
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

%-agent-linux-arm64.so: %-agent.c
	aarch64-linux-gnu-gcc $(CFLAGS) $(LDFLAGS) -shared $< -o $@.tmp
	aarch64-linux-gnu-strip --strip-all $@.tmp
	mv $@.tmp $@

%-agent-linux-mips.so: %-agent.c
	mips-linux-gnu-gcc $(CFLAGS) $(LDFLAGS) -shared $< -o $@.tmp
	mips-linux-gnu-strip --strip-all $@.tmp
	mv $@.tmp $@

%-agent-linux-mipsel.so: %-agent.c
	mipsel-linux-gnu-gcc $(CFLAGS) $(LDFLAGS) -shared $< -o $@.tmp
	mipsel-linux-gnu-strip --strip-all $@.tmp
	mv $@.tmp $@

%-agent-linux-mips64.so: %-agent.c
	mips64-linux-gnuabi64-gcc $(CFLAGS) $(LDFLAGS) -shared $< -o $@.tmp
	mips64-linux-gnuabi64-strip --strip-all $@.tmp
	mv $@.tmp $@

%-agent-linux-mips64el.so: %-agent.c
	mips64el-linux-gnuabi64-gcc $(CFLAGS) $(LDFLAGS) -shared $< -o $@.tmp
	mips64el-linux-gnuabi64-strip --strip-all $@.tmp
	mv $@.tmp $@

.PHONY: all
