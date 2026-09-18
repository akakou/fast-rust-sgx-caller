//! cargo run --release --example call -- library.sgxs library.sig op p2 p3 p4 p5
use fast_rust_sgx_caller::Caller;
use sgxs::{loader::Load, sigstruct};
use sgxs_loaders::isgx::Device;
use std::fs::File;

fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    anyhow::ensure!(
        args.len() == 8,
        "usage: call library.sgxs library.sig p1 p2 p3 p4 p5"
    );
    let signature = sigstruct::read(&mut File::open(&args[2])?)?;
    let mut device = Device::new()?.build();
    let mut mapping = device.load(
        &mut File::open(&args[1])?,
        &signature,
        signature.attributes,
        signature.miscselect,
    )?;
    let tcs = mapping
        .tcss
        .pop()
        .ok_or_else(|| anyhow::anyhow!("enclave has no TCS"))?;
    let mut caller = Caller::new(tcs)?;
    let p: Vec<u64> = args[3..]
        .iter()
        .map(|v| v.parse())
        .collect::<Result<_, _>>()?;
    // SAFETY: The operator must supply a trusted Fortanix library enclave and
    // arguments valid for its API. Arbitrary integer values are not safe pointers.
    let result = unsafe { caller.call(p[0], p[1], p[2], p[3], p[4])? };
    println!("{}, {}", result.0, result.1);
    Ok(())
}
