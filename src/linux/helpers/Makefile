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

artifacts_dir := artifacts
build_dir := build

native_outdir := $(artifacts_dir)/native/$(host_arch)

bpf_outdir := $(artifacts_dir)/bpf
bpf_noarch_progs := \
	activity-sampler \
	spawn-gater \
	$(NULL)
bpf_arch_progs := \
	syscall-tracer \
	spawn-gater \
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

define recreate_build_dir
	rm -rf $(build_dir)
	mkdir -p $(build_dir)
endef

define bpf_compile
	clang \
		-target $(1) \
		-O2 -g0 \
		-I$(build_dir) \
		$< \
		-c \
		-o $(bpf_obj)
	llvm-strip --strip-debug --strip-unneeded $(bpf_obj)
	mkdir -p $(@D)
	install -m644 $(bpf_obj) $@
endef

define declare-bpf-noarch
bpf_targets += $(foreach p,$(bpf_noarch_progs),$(bpf_outdir)/noarch-$(1)/$(p).elf)

$(bpf_outdir)/noarch-$(1)/%.elf: %.bpf.c
	$$(call recreate_build_dir)
	$$(call bpf_compile,$(2))
endef

define declare-bpf-arch
bpf_targets += $(foreach p,$(bpf_arch_progs),$(bpf_outdir)/$(1)/$(p).elf)

$(bpf_outdir)/$(1)/%.elf: %.bpf.c
	$$(call recreate_build_dir)
	python3 $(top_srcdir)/lib/base/linux-syscalls/generate-bindings.py \
		--abi $(1) \
		--out-c-header $(build_dir)/frida-linux-syscalls.h
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

.PHONY: build-native build-bpf
