# Builds frida-agent.ko in two steps, because kbuild insists on owning the final
# link:
#
#   1. Collapse the Rust staticlib plus everything it needs — the GumJS devkit and
#      the C library — into one relocatable object, and localize every symbol except
#      the entry points frida-kmod.c calls. Localizing matters: Gum and the C library
#      define names like memcpy and malloc that must not leak into the kernel's
#      namespace.
#   2. Hand that object to kbuild as a shipped object, so vermagic, modinfo and
#      CRCs all come from the target kernel's own build system.
#
# See README.md for usage.

# KDIR is the kernel to build against. When it is a source tree that was configured
# elsewhere — which is what Android's modules_prepare tarball gives — point KOUT at
# the prepared tree.
KDIR ?= /lib/modules/$(shell uname -r)/build
ARCH ?= arm64
RUST_TARGET ?= aarch64-unknown-none
PROFILE ?= release

AGENT_DIR := $(CURDIR)/..
AGENT_TARGET_DIR := $(AGENT_DIR)/target-linux
AGENT_LIB := $(AGENT_TARGET_DIR)/$(RUST_TARGET)/$(PROFILE)/libfrida_barebone_agent.a

GUMJS_DEVKIT_DIR ?= $(error Set GUMJS_DEVKIT_DIR to the directory holding libfrida-gumjs.a)

# Any binutils that speak aarch64 ELF will do; nothing here is compiled with them.
AGENT_LD ?= aarch64-none-elf-ld
AGENT_AR ?= aarch64-none-elf-ar
AGENT_NM ?= aarch64-none-elf-nm
AGENT_OBJCOPY ?= aarch64-none-elf-objcopy

# arm64 kernels reserve x18 for the shadow call stack, so nothing we link in may use
# it as a general-purpose register. The flag only reaches crates Cargo compiles, and
# the toolchain ships core, alloc and compiler_builtins prebuilt without it, so those
# three have to be rebuilt from source as well. That needs the rust-src component and
# an unstable flag, hence RUSTC_BOOTSTRAP.
AGENT_RUSTFLAGS ?= -Zfixed-x18
AGENT_BUILD_STD ?= -Z build-std=core,alloc,compiler_builtins

# The soft-float SDK, whose libc is picolibc and whose compiler runtime is
# compiler-rt. GCC's own newlib and libgcc are hard-float and cannot be used here.
FRIDA_SDK ?= $(error Set FRIDA_SDK to a none-arm64-softfloat SDK prefix)
LIBM = $(FRIDA_SDK)/lib/libm.a
LIBBUILTINS = $(FRIDA_SDK)/lib/libclang_rt.builtins.a

# bindgen reads the devkit header through whatever this compiler reports as its
# include path, so it has to be one that knows where the SDK keeps its libc. Only
# clang implements -mabi=aapcs-soft, and only from 19 onwards.
AGENT_CC ?= clang
AGENT_CFLAGS ?= --target=aarch64-none-elf -mabi=aapcs-soft -mgeneral-regs-only \
	-ffixed-x18 -fno-pic --sysroot=$(FRIDA_SDK)

PRELINKED := frida-agent-prelinked.o.bin

# Rust's toolchain ships compiler_builtins compiled for the ordinary AAPCS, where a
# double travels in d0: its __muldf3 opens with "fmov x14, d0". Everything else here
# is -mabi=aapcs-soft and passes that same double in x0. Whole-archiving the staticlib
# puts those definitions in front of the SDK's compiler-rt, which has the soft-float
# ones, and every double the C library computes then comes back garbage — quietly,
# since the arithmetic still runs. Drop them and let compiler-rt answer instead.
AGENT_LIB_SOFTFLOAT := $(AGENT_TARGET_DIR)/libfrida-barebone-agent-softfloat.a

# The agent puts malloc, the C library's locks and its process stubs on the kernel's
# own facilities, so picolibc's versions are duplicate definitions rather than
# fallbacks. Work out which members they live in instead of naming them: the set
# follows from what the agent defines, and picolibc moves things between releases.
LIBC := $(AGENT_TARGET_DIR)/libc-trimmed.a

ENTRY_POINTS := frida_agent_start frida_agent_stop
KEEP_GLOBAL := $(foreach s,$(ENTRY_POINTS),--keep-global-symbol=$(s))

all: modules

modules: $(PRELINKED)
	$(MAKE) -C $(KDIR) $(if $(KOUT),O=$(KOUT)) M=$(CURDIR) ARCH=$(ARCH) modules

$(PRELINKED): $(AGENT_LIB_SOFTFLOAT) $(LIBC)
	$(AGENT_LD) -r -o $@.tmp \
		--whole-archive $(AGENT_LIB_SOFTFLOAT) --no-whole-archive \
		--start-group \
			$(GUMJS_DEVKIT_DIR)/libfrida-gumjs.a \
			$(LIBC) \
			$(LIBM) \
			$(LIBBUILTINS) \
		--end-group
	$(AGENT_OBJCOPY) $(KEEP_GLOBAL) --strip-debug \
		--remove-section=.llvmbc --remove-section=.llvmcmd $@.tmp $@
	rm -f $@.tmp

$(AGENT_LIB_SOFTFLOAT): agent
	cp $(AGENT_LIB) $@
	$(AGENT_AR) d $@ $$($(AGENT_NM) --print-armap $@ | sed -n 's/^__muldf3 in //p')
	$(AGENT_AR) s $@

$(LIBC): $(AGENT_LIB_SOFTFLOAT)
	cp $(FRIDA_SDK)/lib/libc.a $@
	$(AGENT_NM) --defined-only $(AGENT_LIB_SOFTFLOAT) \
		| awk 'NF == 3 && $$2 ~ /^[TDBR]$$/ { print $$3 }' | sort -u > $@.agent-syms
	$(AGENT_NM) --print-armap $@ | sed -n 's/^\([^ ]*\) in \(.*\)$$/\1 \2/p' | sort -u > $@.members
	$(AGENT_AR) d $@ $$(join $@.agent-syms $@.members | awk '{ print $$2 }' | sort -u)
	$(AGENT_AR) s $@
	rm -f $@.agent-syms $@.members

agent:
	cd $(AGENT_DIR) && RUSTC_BOOTSTRAP=1 RUSTFLAGS="$(AGENT_RUSTFLAGS)" \
		CC_aarch64_unknown_none="$(AGENT_CC) $(AGENT_CFLAGS)" \
		cargo build --$(PROFILE) \
		--target $(RUST_TARGET) --features linux \
		--target-dir $(AGENT_TARGET_DIR) $(AGENT_BUILD_STD)

clean:
	$(MAKE) -C $(KDIR) $(if $(KOUT),O=$(KOUT)) M=$(CURDIR) ARCH=$(ARCH) clean
	rm -f $(PRELINKED) $(PRELINKED).tmp $(AGENT_LIB_SOFTFLOAT) $(LIBC)

.PHONY: all modules agent clean
