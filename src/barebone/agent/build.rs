use std::{env, fs, path::PathBuf, process::Command};

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
        .compile("quickjs");

    let bindings = bindgen::Builder::default()
        .header(quickjs_dir.join("quickjs.h").to_str().unwrap())
        .allowlist_function("JS_.*")
        .clang_arg(format!("-I{}", quickjs_dir.to_str().unwrap()))
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Couldn't write bindings");

    println!("cargo:rerun-if-changed=build.rs");
}
