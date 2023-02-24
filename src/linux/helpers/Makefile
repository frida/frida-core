helpers := \
	build/bootstrapper.so build/test-bootstrapper \
	build/loader.so \
	$(NULL)

sources := \
	bootstrapper.c \
	loader.c \
	$(NULL)

cflags := -Wall -pipe -O1 -g -fPIC
ldflags := -Wl,--gc-sections

build: $(helpers)

test: build
	@build/test-bootstrapper

build/%.so: %.c $(sources)
	@mkdir -p $(@D)
	$(CC) \
		$(cflags) \
		$< \
		-o $@ \
		-fno-optimize-strlen \
		-fno-exceptions \
		-fno-asynchronous-unwind-tables \
		-fno-unwind-tables \
		-shared \
		-nostdlib \
		$(ldflags)
	./serialize.py $@ ../frida-helper-backend.vala

build/test-%: %.c $(sources)
	@mkdir -p $(@D)
	$(CC) \
		$(cflags) \
		-DBUILDING_TEST_PROGRAM \
		$< \
		-o $@ \
		$(ldflags)

.PHONY: build test
