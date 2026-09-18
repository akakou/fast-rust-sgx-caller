use fast_rust_sgx_caller::{Caller, Usercall};
use openssl::{bn::BigNum, hash::Hasher, rsa::Rsa};
use sgx_isa::{AttributesFlags, PageType, SecinfoFlags, Sigstruct};
use sgxs::{
    loader::Load,
    sgxs::{CanonicalSgxsWriter, MeasECreate, SecinfoTruncated},
    sigstruct::{EnclaveHash, Signer},
};
use sgxs_loaders::{Tcs, isgx::Device};
use std::sync::OnceLock;

std::arch::global_asm!(include_str!("enclave.S"), exit_usercall = const Usercall::exit as u64);

pub fn image() -> &'static (Vec<u8>, Sigstruct) {
    static IMAGE: OnceLock<(Vec<u8>, Sigstruct)> = OnceLock::new();
    IMAGE.get_or_init(|| {
        unsafe extern "C" {
            static test_enclave_start: u8;
            static test_enclave_end: u8;
        }
        let code = unsafe {
            let start = &test_enclave_start as *const u8;
            let len = &test_enclave_end as *const u8 as usize - start as usize;
            std::slice::from_raw_parts(start, len)
        };
        assert!(code.len() < 4096);
        let mut image = Vec::new();
        let mut writer = CanonicalSgxsWriter::new(
            &mut image,
            MeasECreate {
                ssaframesize: 1,
                size: 16384,
            },
            true,
        )
        .unwrap();
        let tcs = sgx_isa::Tcs {
            ossa: 4096,
            nssa: 1,
            oentry: 8192,
            fslimit: 0xfff,
            gslimit: 0xfff,
            ..Default::default()
        };
        for (data, flags) in [
            (tcs.as_ref(), PageType::Tcs.into()),
            (
                &[][..],
                SecinfoFlags::R | SecinfoFlags::W | PageType::Reg.into(),
            ),
            (
                code,
                SecinfoFlags::R | SecinfoFlags::X | PageType::Reg.into(),
            ),
            (
                &[][..],
                SecinfoFlags::R | SecinfoFlags::W | PageType::Reg.into(),
            ),
        ] {
            writer
                .write_page(Some(&mut &data[..]), None, SecinfoTruncated { flags })
                .unwrap();
        }
        let hash = EnclaveHash::from_stream::<_, Hasher>(&mut &image[..]).unwrap();
        let key = Rsa::generate_with_e(3072, &BigNum::from_u32(3).unwrap()).unwrap();
        let mut signer = Signer::new(hash);
        signer.attributes_flags(AttributesFlags::DEBUG | AttributesFlags::MODE64BIT, !0);
        signer.attributes_xfrm(3, !0);
        let signature = signer.sign::<_, Hasher>(key.as_ref()).unwrap();
        (image, signature)
    })
}

pub fn caller() -> Caller<Tcs> {
    let (image, signature) = image();
    let mut device = Device::new().unwrap().build();
    let mut mapping = device
        .load(
            &mut &image[..],
            signature,
            signature.attributes,
            signature.miscselect,
        )
        .unwrap();
    // The owned TCS keeps the mapping alive after MappingInfo is dropped.
    Caller::new(mapping.tcss.pop().unwrap()).unwrap()
}
