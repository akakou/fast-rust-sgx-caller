# fast-rust-sgx-caller

A Rust library for synchronously executing a Fortanix SGX library-mode enclave on the caller's OS thread.

```text
Caller::call -> vDSO -> EENTER -> enclave -> EEXIT -> return values
                            ^               |
                            `- sync handler <-' usercall
```

There is no need to create a thread, Tokio runtime, or queue for each library call.

## Requirements

* Linux x86-64
* An SGX-enabled kernel providing `__vdso_sgx_enter_enclave`
* Rust 1.88+
* `sgxs`
* `sgxs-loaders`

## Usage

```toml
[dependencies]
fast-rust-sgx-caller = { path = "/path/to/fast-rust-sgx-caller" }
sgxs = "0.9"
sgxs-loaders = "0.5.2"
```

Load a signed library-mode `.sgxs` image and `.sig` file, then create a `Caller` from a TCS.

```rust,no_run
use fast_rust_sgx_caller::Caller;
use sgxs::{loader::Load, sigstruct};
use sgxs_loaders::isgx::Device;
use std::fs::File;

# fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
let signature = sigstruct::read(&mut File::open("library.sig")?)?;
let mut device = Device::new()?.build();

let mut mapping = device.load(
    &mut File::open("library.sgxs")?,
    &signature,
    signature.attributes,
    signature.miscselect,
)?;

let tcs = mapping.tcss.pop().expect("at least one library TCS");
let mut caller = Caller::new(tcs)?;

let (r1, r2) = unsafe { caller.call(1, 17, 29, 0, 0)? };
# Ok(())
# }
```

Example:

```sh
cargo run --release --example call -- library.sgxs library.sig 1 17 29 0 0
```

The Fortanix library entry ABI uses six arguments and two return values. The fourth argument is reserved by the ABI, so the host-side `call` method takes five arguments.

```rust,ignore
pub extern "C" fn entry(
    op: u64,
    p2: u64,
    p3: u64,
    _reserved: u64,
    p4: u64,
    p5: u64,
) -> (u64, u64) {
    (p2.wrapping_add(p4), p3.wrapping_add(p5))
}
```

## Usercalls

The default handler supports the following usercalls:

| Usercall                        | Behavior                              |
| ------------------------------- | ------------------------------------- |
| `insecure_time`                 | Returns the time since the UNIX epoch |
| `exit`                          | Returns `Error::Exit`                 |
| `launch_thread`, `async_queues` | Returns an ABI error                  |
| Any other usercall              | Returns `Error::UnsupportedUsercall`  |

Custom usercalls can be handled synchronously with `call_with`.

```rust,no_run
use fast_rust_sgx_caller::{Caller, Error, default_usercall};

# unsafe fn example<T: sgxs::loader::Tcs>(
#     caller: &mut Caller<T>
# ) -> Result<(), Error> {
let result = unsafe {
    caller.call_with([1, 17, 29, 0, 0], |number, args| {
        if number == 0x8000_0001 {
            Ok((args[0].wrapping_add(args[1]), 0))
        } else {
            default_usercall(number, args)
        }
    })?
};
# Ok(())
# }
```

The default implementation does not provide `alloc/free`, standard output, file or network I/O, or `wait/send`. If you need these features, implement them with `call_with` or use the official runner.

## Safety

`call` and `call_with` are `unsafe`.

The caller must ensure that:

* the enclave follows the Fortanix library ABI;
* all pointers, lengths, lifetimes, and writable ranges passed to the enclave are valid;
* lengths and pointers returned by the enclave are validated before use;
* the usercall handler does not allow unauthorized access to arbitrary host memory.

Each `Caller` owns a single TCS. Its `&mut self` interface prevents concurrent entry into the same TCS.

For parallel execution, use a separate `Caller` for each TCS.

After an error, CPU exception, or handler unwind, the `Caller` enters a stopped state and all subsequent calls return `Error::Stopped`.

Enclaves that require an asynchronous usercall queue are not supported.

## Test

```sh
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
```

SGX hardware tests:

```sh
cargo test --locked --release --test sgx -- \
  --ignored --nocapture --test-threads=1
```


## References

* [Fortanix library entry ABI](https://docs.rs/fortanix-sgx-abi/0.6.1/fortanix_sgx_abi/entry/library/index.html)
* [Linux SGX vDSO ABI](https://www.kernel.org/doc/html/latest/arch/x86/sgx.html)

