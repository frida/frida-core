export FRIDA_BAREBONE_CONFIG=$PWD/etc/xnu.json
export PYTHONPATH=$HOME/src/frida-python

export PATH=$PWD/xpacks/.bin:$PATH
export CC_aarch64_unknown_none=aarch64-none-elf-gcc
export AR_aarch64_unknown_none=aarch64-none-elf-ar
export RANLIB_aarch64_unknown_none=aarch64-none-elf-ranlib
export GUMJS_DEVKIT_DIR=/Users/oleavr/src/frida-gum/build/bindings/gumjs/devkit
