FRIDA_MONOREPO ?= ../../../..

ifdef FRIDA_HOST
host_os := $(shell echo $(FRIDA_HOST) | cut -f1 -d"-")
host_arch := $(shell echo $(FRIDA_HOST) | cut -f2 -d"-")
else
host_os := $(shell $(FRIDA_MONOREPO)/releng/detect-os.sh)
host_arch := $(shell $(FRIDA_MONOREPO)/releng/detect-arch.sh)
endif

build: $(FRIDA_MONOREPO)/build/frida*-$(host_os)-$(host_arch).txt ext/linux/tools/include/nolibc/nolibc.h
	rm -rf build
	meson setup --cross-file $< -Db_lto=true build
	meson compile -C build
	cp build/bootstrapper.bin bootstrapper-$(host_arch).bin
	cp build/loader.bin loader-$(host_arch).bin

ext/linux/tools/include/nolibc/nolibc.h: nolibc-tweaks.patch
	if [ -d ext/linux ]; then \
		cd ext/linux; \
		git reset --hard; \
		git checkout v6.2; \
	else \
		git clone --branch=v6.2 --depth=1 https://github.com/torvalds/linux.git ext/linux; \
	fi
	patch -d ext/linux -p1 < nolibc-tweaks.patch
	@touch -c $@

.PHONY: build
