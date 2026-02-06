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

crossfile := $(BUILDDIR)/$(host_machine)/frida-$(host_machine).txt
ebpf_cc := $(shell grep "c = " $(crossfile) | cut -c6- | cut -d] -f1 | sed -e "s/,//g")
ebpf_strip := $(shell grep "strip = " $(crossfile) | cut -c10- | sed "s,'--strip-all',," | sed -e "s/.$$//" -e "s/,//g")
valac := $(shell grep "vala = " $(crossfile) | cut -c9- | sed -e "s/.$$//" -e "s/,//g")

artifacts_dir := artifacts
build_dir := build

native_outdir := $(artifacts_dir)/native/$(host_arch)

bpf_outdir := $(artifacts_dir)/bpf
bpf_noarch_progs := \
	activity-sampler \
	$(NULL)
bpf_arch_progs := \
	syscall-tracer \
	$(NULL)
bpf_noarch_pairs := \
	big:bpfeb \
	little:bpfel
bpf_arch_pairs := \
	x86:bpfel x86_64:bpfel \
	arm:bpfel armbe:bpfeb arm64:bpfel arm64be:bpfeb \
	mips:bpfeb mipsel:bpfel mips64:bpfeb mips64el:bpfel \
	$(NULL)

build-native: ext/linux/tools/include/nolibc/nolibc.h
	rm -rf build
	$(MESON) setup --cross-file $(crossfile) -Db_lto=true build
	$(MESON) compile -C build
	install -m644 build/bootstrapper.bin $(native_outdir)/bootstrapper.bin
	install -m644 build/loader.bin $(native_outdir)/loader.bin
	[ -f build/zymbiote.bin ] && install -m644 build/zymbiote.bin $(native_outdir)/zymbiote.bin || true

bpf_targets :=
bpf_obj := $(build_dir)/module.o

kernel_headers_url := https://kojipkgs.fedoraproject.org//packages/kernel/6.19.0/0.rc8.54.eln154/x86_64/kernel-headers-6.19.0-0.rc8.54.eln154.x86_64.rpm
kernel_headers_rpm := $(notdir $(kernel_headers_url))
kernel_headers_dir := ext/kernel-headers

libbpf_devel_url := https://kojipkgs.fedoraproject.org//packages/libbpf/1.6.3/1.fc44/x86_64/libbpf-devel-1.6.3-1.fc44.x86_64.rpm
libbpf_devel_rpm := $(notdir $(libbpf_devel_url))
libbpf_devel_dir := ext/libbpf

define recreate_build_dir
	rm -rf $(build_dir)
	mkdir -p $(build_dir)
endef

define bpf_compile
	$(ebpf_cc) \
		-target $(1) \
		-O2 -g0 \
		-I$(build_dir) \
		-I$(kernel_headers_dir) \
		-I$(libbpf_devel_dir) \
		$< \
		-c \
		-o $(bpf_obj)
	$(ebpf_strip) --strip-debug --strip-unneeded $(bpf_obj)
	mkdir -p $(@D)
	install -m644 $(bpf_obj) $@
endef

define declare-bpf-noarch
bpf_targets += $(foreach p,$(bpf_noarch_progs),$(bpf_outdir)/noarch-$(1)/$(p).elf)

$(bpf_outdir)/noarch-$(1)/%.elf: %.bpf.c $(kernel_headers_dir) $(libbpf_devel_dir)
	$$(call recreate_build_dir)
	$$(call bpf_compile,$(2))
endef

define declare-bpf-arch
bpf_targets += $(foreach p,$(bpf_arch_progs),$(bpf_outdir)/$(1)/$(p).elf)

$(bpf_outdir)/$(1)/%.elf: %.bpf.c $(kernel_headers_dir) $(libbpf_devel_dir)
	$$(call recreate_build_dir)
	syscalls_dir=$$(realpath $(top_srcdir)/lib/base/linux-syscalls); cd build && $$(valac) \
		-C \
		--header=frida-linux-syscalls.h \
		--profile=posix \
		$$$${syscalls_dir}/$(shell echo $(1) | sed -e 's/be$$//' -e 's/el$$//').vala
	$$(call bpf_compile,$(2))
endef

pair_abi    = $(word 1,$(subst :, ,$1))
pair_target = $(word 2,$(subst :, ,$1))

$(foreach pair,$(bpf_noarch_pairs), \
	$(eval $(call declare-bpf-noarch,$(call pair_abi,$(pair)),$(call pair_target,$(pair)))))

$(foreach pair,$(bpf_arch_pairs), \
	$(eval $(call declare-bpf-arch,$(call pair_abi,$(pair)),$(call pair_target,$(pair)))))

build-bpf: $(bpf_targets)

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

$(kernel_headers_dir):
	mkdir -p $(kernel_headers_dir)
	curl -L -o $(kernel_headers_rpm) $(kernel_headers_url)
	rpm2cpio $(kernel_headers_rpm) | tar -xpf - \
		-C $(kernel_headers_dir) \
		--strip-components=3 \
		usr/include
	rm -f $(kernel_headers_rpm)

$(libbpf_devel_dir):
	mkdir -p $(libbpf_devel_dir)
	curl -L -o $(libbpf_devel_rpm) $(libbpf_devel_url)
	rpm2cpio $(libbpf_devel_rpm) | tar -xpf - \
		-C $(libbpf_devel_dir) \
		--strip-components=3 \
		usr/include
	rm -f $(libbpf_devel_rpm)

.PHONY: build-native build-bpf
