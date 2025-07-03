use std::{env, path::PathBuf, process::Command};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let quickjs_dir = out_dir.join("quickjs");
    if !quickjs_dir.exists() {
        let status = Command::new("git")
            .args(["clone", "--depth=1", "https://github.com/frida/quickjs", quickjs_dir.to_str().unwrap()])
            .status()
            .expect("Failed to clone QuickJS");
        assert!(status.success());
    }

    cc::Build::new()
        .files([
            quickjs_dir.join("quickjs.c"),
            quickjs_dir.join("libregexp.c"),
            quickjs_dir.join("libunicode.c"),
            quickjs_dir.join("cutils.c"),
            quickjs_dir.join("libbf.c"),
        ])
        .define("CONFIG_VERSION", Some("\"2024-01-13-frida\""))
        .include(&quickjs_dir)
        .flag("-Oz")
        .flag("-ffunction-sections")
        .flag("-fdata-sections")
        .flag("-Wno-cast-function-type")
        .flag("-Wno-enum-conversion")
        .flag("-Wno-implicit-fallthrough")
        .flag("-Wno-sign-compare")
        .flag("-Wno-unused-function")
        .flag("-Wno-unused-parameter")
        .compile("quickjs");

    // FIXME
    let newlib_prefix = PathBuf::from("/Users/oleavr/Library/xPacks/@xpack-dev-tools/aarch64-none-elf-gcc/14.2.1-1.1.1/.content/aarch64-none-elf");
    let newlib_include = newlib_prefix.join("include");
    let newlib_lib = newlib_prefix.join("lib");

    let bindings = bindgen::Builder::default()
        .use_core()
        .header(quickjs_dir.join("quickjs.h").to_str().unwrap())
        .allowlist_var("JS_EVAL_FLAG_.*")
        .allowlist_var("JS_EVAL_TYPE_.*")
        .allowlist_function("JS_.*")
        .clang_arg(format!("-I{}", quickjs_dir.to_str().unwrap()))
        .clang_arg(format!("-I{}", newlib_include.to_str().unwrap()))
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Couldn't write bindings");

    println!("cargo:rustc-link-search=native={}", newlib_lib.to_str().unwrap());
    println!("cargo:rustc-link-lib=static=c");
    println!("cargo:rustc-link-arg=--gc-sections");
    println!("cargo:rustc-link-arg=--script=agent.lds");
    println!("cargo:rerun-if-changed=build.rs");
}
