fn main() {
    #[cfg(feature = "ffi")]
    uniffi::generate_scaffolding("src/pevv_transport.udl").expect("UniFFI scaffolding");
}
