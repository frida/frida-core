## Getting the C toolchain

    npm install -g xpm
    xpm install
    export PATH=$PWD/xpacks/.bin:$PATH

## How to build Gum

    ./configure \
        --host=aarch64-none-elf \
        --enable-gumjs \
        --with-devkits=gum,gumjs \
        --with-devkit-symbol-scope=original
    make
    export GUMJS_DEVKIT_DIR=$PWD/build/bindings/gumjs/devkit

## Building

    export PATH=$PWD/xpacks/.bin:$PATH
    export CC_aarch64_unknown_none=aarch64-none-elf-gcc
    export AR_aarch64_unknown_none=aarch64-none-elf-ar
    export RANLIB_aarch64_unknown_none=aarch64-none-elf-ranlib

## Development loop

    export FRIDA_BAREBONE_CONFIG=$PWD/etc/xnu.json
    cargo build --release && make -C ~/src/frida-python && killall -9 qemu-system-aarch64 && sleep 2 && frida -D barebone -p 0

## Speeding up loop

    ./configure \
        -- \
        -Dfrida-core:compat=disabled \
        -Dfrida-core:local_backend=disabled \
        -Dfrida-core:fruity_backend=disabled \
        -Dfrida-core:droidy_backend=disabled \
        -Dfrida-core:socket_backend=disabled \
        -Dfrida-core:compiler_backend=disabled \
        -Dfrida-core:gadget=disabled \
        -Dfrida-core:server=disabled \
        -Dfrida-core:portal=disabled \
        -Dfrida-core:inject=disabled \
        -Dfrida-core:tests=enabled
