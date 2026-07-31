# Builds frida-agent.ko in two steps, because kbuild insists on owning the final
# link:
#
#   1. Collapse the Rust staticlib plus everything it needs — the GumJS devkit and
#      newlib — into one relocatable object, and localize every symbol except the
#      entry points frida-kmod.c calls. Localizing matters: Gum and newlib define
#      names like memcpy and malloc that must not leak into the kernel's namespace.
#   2. Hand that object to kbuild as a shipped object, so vermagic, modinfo and
#      CRCs all come from the target kernel's own build system.
#
# See README.md for usage.

KDIR ?= /lib/modules/$(shell uname -r)/build
ARCH ?= arm64
RUST_TARGET ?= aarch64-unknown-none
PROFILE ?= release

AGENT_DIR := $(CURDIR)/..
AGENT_TARGET_DIR := $(AGENT_DIR)/target-linux
AGENT_LIB := $(AGENT_TARGET_DIR)/$(RUST_TARGET)/$(PROFILE)/libfrida_barebone_agent.a

GUMJS_DEVKIT_DIR ?= $(error Set GUMJS_DEVKIT_DIR to the directory holding libfrida-gumjs.a)

# The same freestanding toolchain the agent itself is built with, so the newlib and
# libgcc archives match the objects that reference them.
AGENT_CC ?= aarch64-none-elf-gcc
AGENT_LD ?= aarch64-none-elf-ld
AGENT_OBJCOPY ?= aarch64-none-elf-objcopy

# arm64 kernels reserve x18 for the shadow call stack, so nothing we link in may
# use it as a general-purpose register.
AGENT_RUSTFLAGS ?= -C target-feature=+reserve-x18

LIBC := $(shell $(AGENT_CC) -print-file-name=libc.a)
LIBM := $(shell $(AGENT_CC) -print-file-name=libm.a)
LIBGCC := $(shell $(AGENT_CC) -print-libgcc-file-name)

PRELINKED := frida-agent-prelinked.o.bin

ENTRY_POINTS := frida_agent_start frida_agent_stop
KEEP_GLOBAL := $(foreach s,$(ENTRY_POINTS),--keep-global-symbol=$(s))

all: modules

modules: $(PRELINKED)
	$(MAKE) -C $(KDIR) M=$(CURDIR) ARCH=$(ARCH) modules

$(PRELINKED): agent
	$(AGENT_LD) -r -o $@.tmp \
		--whole-archive $(AGENT_LIB) --no-whole-archive \
		--start-group \
			$(GUMJS_DEVKIT_DIR)/libfrida-gumjs.a \
			$(LIBC) \
			$(LIBM) \
			$(LIBGCC) \
		--end-group
	$(AGENT_OBJCOPY) $(KEEP_GLOBAL) --strip-debug \
		--remove-section=.llvmbc --remove-section=.llvmcmd $@.tmp $@
	rm -f $@.tmp

agent:
	cd $(AGENT_DIR) && RUSTFLAGS="$(AGENT_RUSTFLAGS)" cargo build --$(PROFILE) \
		--target $(RUST_TARGET) --features linux \
		--target-dir $(AGENT_TARGET_DIR)

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) ARCH=$(ARCH) clean
	rm -f $(PRELINKED) $(PRELINKED).tmp

.PHONY: all modules agent clean
