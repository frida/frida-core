use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rustc-link-arg=--export-dynamic");
    println!("cargo:rustc-link-arg=--emit-relocs");
    println!("cargo:rustc-link-arg=--discard-all");
    println!("cargo:rustc-link-arg=--strip-debug");
    println!("cargo:rustc-link-arg=--script=allocvera.lds");
    println!("cargo:rustc-link-arg=--gc-sections");
    println!("cargo:rerun-if-changed=build.rs");
}
