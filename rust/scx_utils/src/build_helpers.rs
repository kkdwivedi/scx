// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;
use glob::glob;
use libbpf_cargo::SkeletonBuilder;
use sscanf::sscanf;
use std::env;
use std::path::Path;
use std::path::PathBuf;

const BPF_H_TAR: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/bpf_h.tar"));

pub fn install_bpf_h<P: AsRef<Path>>(dest: P) -> Result<()> {
    let mut ar = tar::Archive::new(BPF_H_TAR);
    ar.unpack(dest)?;
    Ok(())
}

pub fn vmlinux_h_version() -> (String, String) {
    let mut ar = tar::Archive::new(BPF_H_TAR);

    for file in ar.entries().unwrap() {
        let file = file.unwrap();
        if file.header().path().unwrap() != Path::new("vmlinux/vmlinux.h") {
            continue;
        }

        let name = file
            .link_name()
            .unwrap()
            .unwrap()
            .to_string_lossy()
            .to_string();

        return sscanf!(name, "vmlinux-v{String}-g{String}.h").unwrap();
    }

    panic!("vmlinux/vmlinux.h not found");
}

pub fn bindgen_bpf_intf(bpf_intf_rs: Option<&str>, intf_h: Option<&str>) {
    let intf_h = intf_h.unwrap_or("src/bpf/intf.h");
    let bpf_intf_rs = bpf_intf_rs.unwrap_or("bpf_intf.rs");

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed={}", intf_h);

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // Should run clang with the same -I options as BPF compilation.
        .clang_args(env::var("BPF_CFLAGS").unwrap().split_whitespace())
        // The input header we would like to generate
        // bindings for.
        .header(intf_h)
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join(bpf_intf_rs))
        .expect("Couldn't write bindings!");
}

pub fn gen_bpf_skel(skel_name: Option<&str>, main_bpf_c: Option<&str>, deps: Option<&Vec<&str>>) {
    let main_bpf_c = main_bpf_c.unwrap_or("src/bpf/main.bpf.c");
    let skel_name = skel_name.unwrap_or("bpf");

    let bpf_cflags = env::var("BPF_CFLAGS").unwrap();
    let bpf_clang = env::var("BPF_CLANG").unwrap();

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let obj = out_path.join(format!("{}.bpf.o", skel_name));
    let skel_path = out_path.join(format!("{}_skel.rs", skel_name));

    SkeletonBuilder::new()
        .source(main_bpf_c)
        .obj(&obj)
        .clang(bpf_clang)
        .clang_args(bpf_cflags)
        .build_and_generate(&skel_path)
        .unwrap();

    // Trigger rebuild if any .[hc] files are changed in the source
    // directory.
    match deps {
        Some(deps) => {
            for path in deps {
                println!("cargo:rerun-if-changed={}", path);
            }
        }
        None => {
            let c_path = PathBuf::from(main_bpf_c);
            let dir = c_path.parent().unwrap().to_string_lossy();

            for path in glob(&format!("{}/*.[hc]", dir))
                .unwrap()
                .filter_map(Result::ok)
            {
                println!("cargo:rerun-if-changed={}", path.to_str().unwrap());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::BufRead;
    use std::io::BufReader;

    #[test]
    fn test_install_bpf_h() {
        let dir = concat!(env!("OUT_DIR"), "/test_install_bpf_h");
        super::install_bpf_h(dir).unwrap();

        let vmlinux_h = File::open(format!("{}/vmlinux/vmlinux.h", dir)).unwrap();
        assert_eq!(
            BufReader::new(vmlinux_h).lines().next().unwrap().unwrap(),
            "#ifndef __VMLINUX_H__"
        );
    }

    #[test]
    fn test_vmlinux_h_version() {
        let (ver, sha1) = super::vmlinux_h_version();

        println!("test_vmlinux_h_version: ver={:?} sha1={:?}", &ver, &sha1,);

        assert!(
            regex::Regex::new(r"^[1-9][0-9]*\.[1-9][0-9]*(\.[1-9][0-9]*)?$")
                .unwrap()
                .is_match(&ver)
        );
        assert!(regex::Regex::new(r"^[0-9a-z]{12}$")
            .unwrap()
            .is_match(&sha1));
    }
}