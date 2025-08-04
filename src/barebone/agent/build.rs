use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let devkit_dir = PathBuf::from(env::var("GUMJS_DEVKIT_DIR").unwrap());

    let cc_str = env::var("CC_aarch64_unknown_none")
            .or_else(|_| env::var("CC"))
            .unwrap_or_else(|_| "cc".to_string());
    let cc = Path::new(&cc_str);
    let cc_include_paths = detect_gcc_include_paths(cc);
    let cc_library_paths = detect_gcc_library_paths(cc);

    let cc_clang_args: Vec<String> = cc_include_paths
        .iter()
        .flat_map(|path| vec!["-isystem".to_string(), path.to_string_lossy().into_owned()])
        .collect();

    let bindings = bindgen::Builder::default()
        .use_core()
        .header(devkit_dir.join("frida-gumjs.h").to_str().unwrap())
        .clang_arg("-nostdinc")
        .clang_arg("-target")
        .clang_arg("aarch64-none-elf")
        .clang_args(cc_clang_args)
        .clang_arg(format!("-I{}", devkit_dir.to_str().unwrap()))
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
    for path in cc_library_paths {
        println!("cargo:rustc-link-search=native={}", path.to_string_lossy());
    }
    println!("cargo:rustc-link-lib=static=c");
    println!("cargo:rustc-link-lib=static=m");
    println!("cargo:rustc-link-arg=--export-dynamic");
    println!("cargo:rustc-link-arg=--emit-relocs");
    println!("cargo:rustc-link-arg=--script=agent.lds");
    println!("cargo:rustc-link-arg=--gc-sections");
    println!("cargo:rerun-if-changed=build.rs");
}

pub fn detect_gcc_include_paths(gcc: &Path) -> Vec<PathBuf> {
    let out = Command::new(gcc)
        .args(["-xc", "-E", "-v", "-"])
        .stdin(Stdio::null())
        .output()
        .expect("Failed to execute GCC to detect include paths");

    let stderr = String::from_utf8_lossy(&out.stderr);

    let mut grab = false;
    let mut paths = Vec::<PathBuf>::new();

    for line in stderr.lines() {
        if line.starts_with("#include <...> search starts here:") {
            grab = true;
            continue;
        }
        if line.starts_with("End of search list.") {
            break;
        }
        if !grab {
            continue;
        }

        let raw = line.trim();
        if raw.is_empty() {
            continue;
        }

        let p = Path::new(raw);
        if p.exists() {
            let canonical = fs::canonicalize(p).expect("Failed to canonicalize include path");
            if !paths.contains(&canonical) {
                paths.push(canonical);
            }
        }
    }

    paths
}

pub fn detect_gcc_library_paths(gcc: &Path) -> Vec<PathBuf> {
    let out = Command::new(gcc).arg("-print-search-dirs").output()
        .expect("Failed to execute GCC to detect library paths");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.lines().find(|l| l.starts_with("libraries:"))
        .expect("Failed to find libraries line in GCC output");

    let raw_dirs = line.trim_start_matches("libraries: =");
    let sep = if cfg!(windows) { ';' } else { ':' };

    let mut paths = Vec::new();
    for raw in raw_dirs.split(sep) {
        if raw.is_empty() {
            continue;
        }

        let p = Path::new(raw);
        if !p.exists() {
            continue;
        }

        let canonical = fs::canonicalize(p).expect("Failed to canonicalize library path");
        if !paths.contains(&canonical) {
            paths.push(canonical);
        }
    }

    paths
}
