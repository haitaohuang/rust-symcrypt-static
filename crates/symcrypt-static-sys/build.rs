use std::{env, path::PathBuf, process::Command};

fn run(command: &mut Command) {
    let status = command.status().expect("failed to start native build tool");
    assert!(status.success(), "native build failed: {command:?}");
}

fn main() {
    let target = env::var("TARGET").expect("Cargo TARGET");
    assert!(
        target == "x86_64-unknown-linux-gnu" || target == "x86_64-unknown-none",
        "unsupported target {target}; only x86_64 Linux and freestanding ELF are supported"
    );
    let source = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"))
        .join("native");
    assert!(
        source.join("SymCrypt/inc/symcrypt.h").is_file(),
        "native source missing; run git submodule update --init --recursive"
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo OUT_DIR"));
    let build = out.join("native");
    let checked = env::var_os("CARGO_FEATURE_CHECKED").is_some();
    let cc = env::var("CC").unwrap_or_else(|_| "clang".into());
    let cxx = env::var("CXX").unwrap_or_else(|_| "clang++".into());
    let mut configure = Command::new("cmake");
    configure
        .arg("-S")
        .arg(&source)
        .arg("-B")
        .arg(&build)
        .arg("-G")
        .arg("Unix Makefiles")
        .arg(format!("-DCMAKE_C_COMPILER={cc}"))
        .arg(format!("-DCMAKE_CXX_COMPILER={cxx}"))
        .arg(format!(
            "-DCMAKE_BUILD_TYPE={}",
            if checked { "Debug" } else { "Release" }
        ))
        .arg(format!(
            "-DSC_FREESTANDING={}",
            if target.ends_with("-none") {
                "ON"
            } else {
                "OFF"
            }
        ));
    run(&mut configure);
    let jobs = env::var("NUM_JOBS").unwrap_or_else(|_| "2".into());
    run(Command::new("cmake").arg("--build").arg(&build).args([
        "--target",
        "symcrypt_bridge",
        "--parallel",
        &jobs,
    ]));
    println!("cargo:rustc-link-search=native={}/lib", build.display());
    println!(
        "cargo:rustc-link-search=native={}/symcrypt/lib",
        build.display()
    );
    for library in ["symcrypt_bridge", "symcrypt_common", "symcrypt_mlkem"] {
        println!("cargo:rustc-link-lib=static={library}");
    }
    println!("cargo:rerun-if-changed=native");
    for variable in ["CC", "CXX"] {
        println!("cargo:rerun-if-env-changed={variable}");
    }
}
