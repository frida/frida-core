use std::{env, path::PathBuf, process::Command};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let src_dir = manifest_dir.join("src");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let quickjs_dir = out_dir.join("quickjs");
    if !quickjs_dir.exists() {
        let status = Command::new("git")
            .args([
                "clone",
                "--depth=1",
                "https://github.com/frida/quickjs",
                quickjs_dir.to_str().unwrap(),
            ])
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
            src_dir.join("quickjs-glue.c"),
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

    let target_cc = env::var("CC_aarch64_unknown_none")
        .or_else(|_| env::var("CC"))
        .unwrap_or_else(|_| "cc".to_string());

    let sysroot_output = Command::new(&target_cc)
        .arg("-print-sysroot")
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "Failed to get sysroot from {} - make sure it's in PATH: {}",
                target_cc, e
            )
        });

    if !sysroot_output.status.success() {
        panic!(
            "{} -print-sysroot failed: {}",
            target_cc,
            String::from_utf8_lossy(&sysroot_output.stderr)
        );
    }
    let sysroot_str = String::from_utf8(sysroot_output.stdout)
        .expect("Invalid UTF-8 in sysroot output")
        .trim()
        .to_string();

    let newlib_prefix = PathBuf::from(sysroot_str);
    let newlib_include = newlib_prefix.join("include");
    let newlib_lib = newlib_prefix.join("lib");
    if !newlib_include.exists() {
        panic!(
            "newlib include directory not found at: {}",
            newlib_include.display()
        );
    }
    if !newlib_lib.exists() {
        panic!(
            "newlib lib directory not found at: {}",
            newlib_lib.display()
        );
    }

    let bindings = bindgen::Builder::default()
        .use_core()
        .header(src_dir.join("quickjs-glue.h").to_str().unwrap())
        .allowlist_var("JS_EVAL_FLAG_.*")
        .allowlist_var("JS_EVAL_TYPE_.*")
        .allowlist_var("JS_TAG_.*")
        .allowlist_function("JS_.*")
        .allowlist_function("JSGlue_.*")
        .clang_arg(format!("-I{}", quickjs_dir.to_str().unwrap()))
        .clang_arg(format!("-I{}", newlib_include.to_str().unwrap()))
        .merge_extern_blocks(true)
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Couldn't write bindings");

    println!(
        "cargo:rustc-link-search=native={}",
        newlib_lib.to_str().unwrap()
    );
    println!("cargo:rustc-link-lib=static=c");
    println!("cargo:rustc-link-lib=static=m");
    println!("cargo:rustc-link-arg=--export-dynamic");
    println!("cargo:rustc-link-arg=--emit-relocs");
    println!("cargo:rustc-link-arg=--discard-all");
    println!("cargo:rustc-link-arg=--strip-debug");
    println!("cargo:rustc-link-arg=--script=agent.lds");
    println!("cargo:rustc-link-arg=--gc-sections");
    println!("cargo:rerun-if-changed=build.rs");
    println!(
        "cargo:rerun-if-changed={}",
        src_dir.join("quickjs-glue.c").to_str().unwrap()
    );
    println!(
        "cargo:rerun-if-changed={}",
        src_dir.join("quickjs-glue.h").to_str().unwrap()
    );
}
