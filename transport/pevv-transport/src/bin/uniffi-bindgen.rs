//! Generates Kotlin bindings from `src/pevv_transport.udl`:
//! `cargo run --features bindgen --bin uniffi-bindgen -- generate src/pevv_transport.udl --language kotlin --out-dir <dir>`
fn main() {
    uniffi::uniffi_bindgen_main()
}
