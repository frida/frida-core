use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let devkit_dir = PathBuf::from(env::var("GUMJS_DEVKIT_DIR").unwrap());

    let target = env::var("TARGET").unwrap();
    let cc_str = env::var(format!("CC_{}", target.replace('-', "_")))
            .or_else(|_| env::var("CC"))
            .unwrap_or_else(|_| "cc".to_string());
    // Same convention as cc-rs: the variable may carry flags, and a bare-metal
    // compiler needs them to find its libc at all.
    let mut cc_argv = cc_str.split_whitespace();
    let cc = Path::new(cc_argv.next().unwrap());
    let cc_args: Vec<&str> = cc_argv.collect();
    let cc_include_paths = detect_gcc_include_paths(cc, &cc_args);
    let cc_library_paths = detect_gcc_library_paths(cc, &cc_args);

    let cc_clang_args: Vec<String> = cc_include_paths
        .iter()
        .flat_map(|path| vec!["-isystem".to_string(), path.to_string_lossy().into_owned()])
        .collect();

    let bindings = bindgen::Builder::default()
        .use_core()
        .header(devkit_dir.join("frida-gumjs.h").to_str().unwrap())
        .clang_arg("-nostdinc")
        .clang_arg("-target")
        .clang_arg(format!("{}-none-elf", target.split('-').next().unwrap()))
        .clang_args(cc_clang_args)
        .clang_arg(format!("-I{}", devkit_dir.to_str().unwrap()))
        .blocklist_type("max_align_t")
        .merge_extern_blocks(true)
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Couldn't write bindings");

    // The Linux flavour is a staticlib: kbuild owns the final link, so it — not
    // us — decides where the devkit and libc archives come from.
    if env::var("CARGO_FEATURE_BLOB").is_ok() {
        println!(
            "cargo:rustc-link-search=native={}",
            devkit_dir.to_str().unwrap()
        );
        println!("cargo:rustc-link-lib=static=frida-gumjs");
        for path in cc_library_paths {
            println!("cargo:rustc-link-search=native={}", path.to_string_lossy());
        }
        for arg in &cc_args {
            if let Some(path) = arg.strip_prefix("-L") {
                println!("cargo:rustc-link-search=native={path}");
            }
        }
        println!("cargo:rustc-link-lib=static=c");
        println!("cargo:rustc-link-lib=static=m");
        println!("cargo:rustc-link-arg=--export-dynamic");
        println!("cargo:rustc-link-arg=--emit-relocs");
        let script = if env::var("CARGO_FEATURE_WIN9X").is_ok() {
            "agent-win9x.lds"
        } else {
            "agent.lds"
        };
        println!("cargo:rustc-link-arg=--script={script}");
        println!("cargo:rustc-link-arg=--gc-sections");
        // All of the agent lives in the library crate, so nothing in the binary
        // references the entrypoint the host calls; keep the linker from
        // dropping it along with the rest of the unreferenced archive members.
        println!("cargo:rustc-link-arg=--undefined=_start");
    }

    println!("cargo:rerun-if-changed=build.rs");
}

pub fn detect_gcc_include_paths(gcc: &Path, args: &[&str]) -> Vec<PathBuf> {
    let out = Command::new(gcc)
        .args(args)
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

pub fn detect_gcc_library_paths(gcc: &Path, args: &[&str]) -> Vec<PathBuf> {
    let out = Command::new(gcc).args(args).arg("-print-search-dirs").output()
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
