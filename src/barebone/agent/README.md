## Getting the SDK and the devkit

The agent is built against the bare soft-float SDK, which carries picolibc and the
compiler runtime, and against a GumJS devkit built for the same flavor. No prebuilt
bundles are published for these, so build both:

    releng/deps.py build --bundle=sdk --host=none-arm64-softfloat_nopic
    mkdir -p ~/sdk-none-arm64-softfloat_nopic
    tar -C ~/sdk-none-arm64-softfloat_nopic -xf deps/sdk-none-arm64-softfloat_nopic.tar.xz

    gum=~/src/frida-gum
    mkdir -p $gum/build/none-arm64-softfloat_nopic
    (cd $gum/build/none-arm64-softfloat_nopic \
        && FRIDA_DEPS=$HOME/src/frida-core/deps CC=clang CXX=clang++ AR=llvm-ar \
            RANLIB=llvm-ranlib NM=llvm-nm STRIP=llvm-strip \
            ../../configure --host=none-arm64-softfloat_nopic --enable-gumjs \
                --with-devkits=gumjs \
        && python3 ../../releng/meson/meson.py configure -Ddevkit_symbol_scope=original \
        && ninja)

## Building

    sdk=~/sdk-none-arm64-softfloat_nopic
    export GUMJS_DEVKIT_DIR=$gum/build/none-arm64-softfloat_nopic/bindings/gumjs/devkit
    export CC="clang -I$sdk/include -I$sdk/include/glib-2.0 -I$sdk/lib/glib-2.0/include \
        -I$sdk/include/capstone -I$sdk/include/json-glib-1.0"
    export RUSTFLAGS="-L native=$sdk/lib"

    RUSTC_BOOTSTRAP=1 cargo build --release --features xnu \
        --target aarch64-unknown-none-softfloat --target-dir target-xnu \
        -Z build-std=core,alloc,compiler_builtins

## Targets

The agent supports two kernels. One of them has to be picked; neither is a
default, since neither follows from the host you build on:

- `xnu` — a freestanding ELF executable that the Barebone backend
  injects into a running kernel from the outside, over a remote stub.
- `linux` — a static library that becomes a kernel module, loaded from the
  inside. See `linux/README.md`.

Everything above the `kernel` module is shared; each backend supplies the same
set of primitives (logging, allocation, threads, waiting, time, symbols) plus its
half of Gum's platform backend (`gum_xnu.rs` / `gum_linux.rs`).

## Development loop

    export FRIDA_BAREBONE_CONFIG=$PWD/etc/xnu.json
    cargo build --release --features xnu --target aarch64-unknown-none-softfloat \
        && make -C ~/src/frida-python \
        && killall -9 qemu-system-aarch64 && sleep 2 \
        && frida -D barebone -p 0

## Speeding up loop

    ./configure \
        -- \
        -Dfrida-core:compat=disabled \
        -Dfrida-core:local_backend=disabled \
        -Dfrida-core:simmy_backend=disabled \
        -Dfrida-core:fruity_backend=disabled \
        -Dfrida-core:droidy_backend=disabled \
        -Dfrida-core:socket_backend=disabled \
        -Dfrida-core:compiler_backend=disabled \
        -Dfrida-core:gadget=disabled \
        -Dfrida-core:server=disabled \
        -Dfrida-core:portal=disabled \
        -Dfrida-core:inject=disabled \
        -Dfrida-core:tests=enabled
