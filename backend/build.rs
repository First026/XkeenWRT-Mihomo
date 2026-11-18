fn main() {
    println!("cargo:rerun-if-env-changed=XKEENWRT_PACKAGE_VERSION");
    println!("cargo:rerun-if-env-changed=XKEENWRT_BUILD_ID");
    println!("cargo:rustc-env=BUILD_TARGET={}", std::env::var("TARGET").unwrap());
}
