## How to build Gum

    ./configure \
        --host=aarch64-none-elf \
        --enable-gumjs \
        --with-devkits=gum,gumjs \
        --with-devkit-symbol-scope=original
    make
    export GUMJS_DEVKIT_DIR=$PWD/build/bindings/gumjs/devkit

## Development loop

    cargo build --release && make -C ~/src/frida-python && killall -9 qemu-system-aarch64 && sleep 10 && frida -D barebone -p 0
