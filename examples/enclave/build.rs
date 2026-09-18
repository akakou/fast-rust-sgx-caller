fn main() {
    // Rust std also exports executable-mode `entry`. For this development
    // fixture, select the application's library entry (linked first).
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("sgx") {
        println!("cargo:rustc-link-arg=--allow-multiple-definition");
    }
}
