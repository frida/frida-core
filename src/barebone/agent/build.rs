use std::{env, path::PathBuf, process::Command};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let devkit_dir = PathBuf::from(env::var("GUMJS_DEVKIT_DIR").unwrap());

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
        .header(devkit_dir.join("frida-gumjs.h").to_str().unwrap())
        .clang_arg(format!("-I{}", devkit_dir.to_str().unwrap()))
        .clang_arg(format!("-I{}", newlib_include.to_str().unwrap()))
        .merge_extern_blocks(true)
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Couldn't write bindings");

    println!(
        "cargo:rustc-link-search=native={}",
        devkit_dir.to_str().unwrap()
    );
    println!("cargo:rustc-link-lib=static=frida-gumjs");
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
}
