//! Load a development enclave with a freshly generated DEBUG signature.
//! cargo run --release --example smoke -- /path/to/caller-smoke-enclave.sgxs
use fast_rust_sgx_caller::Caller;
use openssl::{bn::BigNum, hash::Hasher, rsa::Rsa};
use sgx_isa::AttributesFlags;
use sgxs::{
    loader::Load,
    sigstruct::{EnclaveHash, Signer},
};
use sgxs_loaders::isgx::Device;

fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: smoke enclave.sgxs"))?;
    let image = std::fs::read(path)?;
    let hash = EnclaveHash::from_stream::<_, Hasher>(&mut &image[..])?;
    let exponent = BigNum::from_u32(3)?;
    let key = Rsa::generate_with_e(3072, &exponent)?;
    let mut signer = Signer::new(hash);
    signer.attributes_flags(AttributesFlags::DEBUG | AttributesFlags::MODE64BIT, !0);
    signer.attributes_xfrm(3, !0);
    let signature = signer.sign::<_, Hasher>(key.as_ref())?;
    let mut device = Device::new()?.build();
    let mut mapping = device.load(
        &mut &image[..],
        &signature,
        signature.attributes,
        signature.miscselect,
    )?;
    let mut caller = Caller::new(
        mapping
            .tcss
            .pop()
            .ok_or_else(|| anyhow::anyhow!("no TCS"))?,
    )?;
    for i in 1..=1000 {
        // The accompanying enclave takes only integers and keeps no host pointers.
        assert_eq!(unsafe { caller.call(1, 17, 29, 31, 37)? }, (114, i));
        let (time, unused) = unsafe { caller.call(2, 0, 0, 0, 0)? };
        assert!(time > 0);
        assert_eq!(unused, 0);
    }
    println!("Rust std smoke: 1000 calls with Vec/OnceLock/Mutex, 1000 time calls passed");
    Ok(())
}
