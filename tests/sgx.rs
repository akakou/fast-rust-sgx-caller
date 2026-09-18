//! Opt-in hardware tests. No SGX target toolchain or AESM is required.
mod common;

use fast_rust_sgx_caller::{Error, Usercall};
use std::hint::black_box;
use std::time::Instant;

#[test]
#[ignore = "requires Linux SGX with flexible launch control"]
fn calls_and_usercalls() {
    let mut caller = common::caller();
    for i in 1..100 {
        assert_eq!(
            unsafe { caller.call(1, i, i + 1, i + 2, i + 3).unwrap() },
            (2 * i + 2, 2 * i + 4)
        );
        let (time, ptr) = unsafe {
            caller
                .call(2, Usercall::insecure_time as u64, 0, 0, 0)
                .unwrap()
        };
        assert!(time > 0);
        assert_eq!(ptr, 0);
    }
    // ABI failures that return normally must leave the TCS reusable.
    for n in [Usercall::async_queues, Usercall::launch_thread] {
        assert_ne!(unsafe { caller.call(2, n as u64, 0, 0, 0).unwrap().0 }, 0);
    }
    // Multiple yields in one invocation; verifies continuation, not replay.
    let mut seen = Vec::new();
    let result = unsafe {
        caller
            .call_with([5, 0, 0, 0, 0], |n, args| {
                assert_eq!(n, 0x80000001);
                seen.push(args[0]);
                assert_eq!(&args[1..], &[0, 0, 0]);
                Ok((args[0] * 10, 0))
            })
            .unwrap()
    };
    assert_eq!(result, (60, 0));
    assert_eq!(seen, [3, 2, 1]);
    assert_eq!(unsafe { caller.call(1, 17, 29, 0, 0).unwrap() }, (17, 29));
    // TCS ownership allows migration to a persistent host worker.
    std::thread::spawn(move || {
        assert_eq!(unsafe { caller.call(1, 9, 11, 0, 0).unwrap() }, (9, 11));
    })
    .join()
    .unwrap();
}

#[test]
#[ignore = "requires Linux SGX with flexible launch control"]
fn failures_stop_the_caller() {
    for (op, number) in [(2, u64::MAX), (2, Usercall::exit as u64), (3, 0), (4, 0)] {
        let mut caller = common::caller();
        let err = unsafe { caller.call(op, number, 0, 0, 0).unwrap_err() };
        match op {
            2 if number == u64::MAX => assert!(matches!(err, Error::UnsupportedUsercall(u64::MAX))),
            2 => assert!(matches!(err, Error::Exit { panic: false, .. })),
            3 => assert!(matches!(err, Error::Exit { panic: true, message } if message == "X")),
            4 => assert!(matches!(err, Error::Entry { vector: 6, .. })),
            _ => unreachable!(),
        }
        assert!(matches!(
            unsafe { caller.call(1, 0, 0, 0, 0) },
            Err(Error::Stopped)
        ));
    }
    let mut caller = common::caller();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        caller.call_with([2, 123, 0, 0, 0], |_, _| panic!("handler panic"))
    }));
    assert!(panic.is_err());
    assert!(matches!(
        unsafe { caller.call(1, 0, 0, 0, 0) },
        Err(Error::Stopped)
    ));
}

fn measure(name: &str, n: usize, mut call: impl FnMut()) {
    for _ in 0..200 {
        call();
    }
    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let start = Instant::now();
        call();
        samples.push(start.elapsed().as_nanos() as u64);
    }
    samples.sort_unstable();
    println!(
        "{name},n={n},mean_ns={:.1},p50_ns={},p95_ns={},p99_ns={}",
        samples.iter().sum::<u64>() as f64 / n as f64,
        samples[n / 2],
        samples[n * 95 / 100],
        samples[n * 99 / 100]
    );
}

#[test]
#[ignore = "requires Linux SGX with flexible launch control"]
fn benchmark() {
    let n = std::env::var("SGX_BENCH_ITERS")
        .map(|s| s.parse().unwrap())
        .unwrap_or(10000);
    assert!(n >= 100);
    let mode = std::env::var("SGX_BENCH_MODE").unwrap_or_else(|_| "all".into());
    assert!(["all", "fast", "official"].contains(&mode.as_str()));
    if mode != "official" {
        let mut caller = common::caller();
        measure("fast_return", n, || {
            assert_eq!(
                unsafe { caller.call(1, black_box(17), 29, 0, 0).unwrap() },
                (17, 29)
            );
        });
        measure("fast_time", n, || {
            assert!(
                unsafe {
                    caller
                        .call(2, Usercall::insecure_time as u64, 0, 0, 0)
                        .unwrap()
                        .0
                } > 0
            );
        });
    }
    if mode != "fast" {
        let (image, signature) = common::image();
        let mut device = sgxs_loaders::isgx::Device::new().unwrap().build();
        let mut builder = enclave_runner_sgx::EnclaveBuilder::new_from_memory(image);
        builder.sigstruct(signature.clone());
        let library: enclave_runner::Library = enclave_runner::EnclaveBuilder::new(builder)
            .build(&mut device)
            .unwrap();
        measure("official_return", n, || {
            assert_eq!(
                unsafe { library.call(1, black_box(17), 29, 0, 0).unwrap() },
                (17, 29)
            );
        });
        measure("official_time", n, || {
            assert!(
                unsafe {
                    library
                        .call(2, Usercall::insecure_time as u64, 0, 0, 0)
                        .unwrap()
                        .0
                } > 0
            );
        });
    }
}
