CC := gcc
CFLAGS := -Wall -pipe -Os -fPIC -fdata-sections -ffunction-sections
LDFLAGS := -Wl,--gc-sections

all: \
	unixvictim-linux-i386 \
	unixvictim-linux-x86_64 \
	unixattacker-linux-i386.so \
	unixattacker-linux-x86_64.so

unixvictim-linux-i386: unixvictim.c
	$(CC) $(CFLAGS) $(LDFLAGS) -m32 $< -o $@.tmp
	strip --strip-all $@.tmp
	mv $@.tmp $@

unixvictim-linux-x86_64: unixvictim.c
	$(CC) $(CFLAGS) $(LDFLAGS) -m64 $< -o $@.tmp
	strip --strip-all $@.tmp
	mv $@.tmp $@

unixattacker-linux-i386.so: unixattacker.c
	$(CC) $(CFLAGS) $(LDFLAGS) -m32 -shared $< -o $@.tmp
	strip --strip-all $@.tmp
	mv $@.tmp $@

unixattacker-linux-x86_64.so: unixattacker.c
	$(CC) $(CFLAGS) $(LDFLAGS) -m64 -shared $< -o $@.tmp
	strip --strip-all $@.tmp
	mv $@.tmp $@

.PHONY: all
