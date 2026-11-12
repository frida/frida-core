# See README.md for usage.

# KDIR is the kernel to build against. When it is a source tree that was configured
# elsewhere — which is what Android's modules_prepare tarball gives — point KOUT at
# the prepared tree.
KDIR ?= /lib/modules/$(shell uname -r)/build
PROFILE ?= release

ARCH ?= $(shell uname -m \
	| sed -e 's/^i[3-6]86$$/x86/' -e 's/^x86_64$$/x86/' -e 's/^aarch64$$/arm64/')
BITS ?= $(shell uname -m \
	| sed -e 's/^i[3-6]86$$/32/' -e 's/^x86_64$$/64/' -e 's/^aarch64$$/64/')

ifeq ($(ARCH)-$(BITS),x86-32)
RUST_TARGET ?= i686-unknown-none-pic
SDK_ARCH ?= x86
AGENT_RUSTFLAGS ?=
AGENT_CFLAGS ?= --target=i386-none-elf
else ifeq ($(ARCH)-$(BITS),x86-64)
RUST_TARGET ?= x86_64-unknown-none-pic
SDK_ARCH ?= x86_64
AGENT_RUSTFLAGS ?= -Zcf-protection=branch -Cllvm-args=--min-jump-table-entries=65536
AGENT_CFLAGS ?= --target=x86_64-none-elf -fcf-protection=branch -fno-jump-tables
else ifeq ($(ARCH)-$(BITS),arm64-64)
RUST_TARGET ?= aarch64-unknown-none-pic
SDK_ARCH ?= arm64
AGENT_RUSTFLAGS ?=
AGENT_CFLAGS ?= --target=aarch64-none-elf -ffixed-x18
else
$(error Unsupported ARCH "$(ARCH)" and BITS "$(BITS)"; this flavor covers \
	x86/32, x86/64 and arm64/64)
endif

FRIDA_SDK ?= $(error Set FRIDA_SDK to a none-$(SDK_ARCH)-softfloat_pic SDK prefix)
GUMJS_DEVKIT_DIR ?= $(error Set GUMJS_DEVKIT_DIR to the directory holding libfrida-gumjs.a)

AGENT_CC ?= clang
AGENT_CFLAGS += -I$(FRIDA_SDK)/include \
	-I$(FRIDA_SDK)/include/glib-2.0 \
	-I$(FRIDA_SDK)/lib/glib-2.0/include \
	-I$(FRIDA_SDK)/include/capstone \
	-I$(FRIDA_SDK)/include/json-glib-1.0

AGENT_DIR := $(CURDIR)/..
AGENT_TARGET_DIR := $(AGENT_DIR)/target-linux-$(SDK_ARCH)
AGENT_IMAGE := frida-agent.elf

all: modules

# A module that dies in its init path is left wedged under its own name until the
# next boot, so bring-up wants a fresh one per attempt.
MODULE_NAME ?= frida-agent

modules: $(AGENT_IMAGE)
	$(MAKE) -C $(KDIR) $(if $(KOUT),O=$(KOUT)) M=$(CURDIR) ARCH=$(ARCH) \
		MODULE_NAME=$(MODULE_NAME) FRIDA_AGENT_IMAGE=$(CURDIR)/$(AGENT_IMAGE) modules

$(AGENT_IMAGE): agent
	cp $(AGENT_TARGET_DIR)/$(RUST_TARGET)/$(PROFILE)/frida-barebone-agent $@

agent:
	cd $(AGENT_DIR) && RUSTC_BOOTSTRAP=1 \
		RUSTFLAGS="-L native=$(FRIDA_SDK)/lib $(AGENT_RUSTFLAGS)" \
		CC="$(AGENT_CC) $(AGENT_CFLAGS)" \
		GUMJS_DEVKIT_DIR=$(GUMJS_DEVKIT_DIR) \
		cargo build --$(PROFILE) --features linux-injected \
		--target ./$(RUST_TARGET).json -Z json-target-spec \
		--target-dir $(AGENT_TARGET_DIR) -Z build-std=core,alloc,compiler_builtins

clean:
	$(MAKE) -C $(KDIR) $(if $(KOUT),O=$(KOUT)) M=$(CURDIR) ARCH=$(ARCH) clean
	rm -f $(AGENT_IMAGE)

.PHONY: all modules agent clean
