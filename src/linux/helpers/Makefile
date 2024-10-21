top_srcdir := ../../..
releng := $(top_srcdir)/releng

BUILDDIR ?= $(top_srcdir)/build
MESON ?= $(releng)/meson/meson.py

ifdef FRIDA_HOST
host_machine := $(FRIDA_HOST)
else
host_machine := $(shell basename $$(ls -1 $(BUILDDIR)/frida-linux-*.txt | tail -1) | cut -d"." -f1 | cut -d"-" -f2-)
endif
host_arch := $(shell echo $(host_machine) | cut -d"-" -f2)

crossfile := $(BUILDDIR)/frida-$(host_machine).txt

build: ext/linux/tools/include/nolibc/nolibc.h
	rm -rf build
	$(MESON) setup --cross-file $(crossfile) -Db_lto=true build
	$(MESON) compile -C build
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
