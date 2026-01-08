fn main() {
    println!("cargo:rustc-link-lib=pretty-verifier");

    println!("cargo:rustc-link-search=/usr/local/lib");
    
    println!("cargo:rerun-if-changed=build.rs");
}