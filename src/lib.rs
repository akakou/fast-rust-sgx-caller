#![doc = include_str!("../README.md")]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("fast-rust-sgx-caller requires Linux x86-64 with the SGX vDSO");

mod entry;

use sgxs::loader::Tcs;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

// Derive the numbering from the official ABI, rather than hard-coding it.
macro_rules! usercall_numbers {
    ($(fn $name:ident($($arg:ident: $ty:ty),*) $(-> $ret:tt)?;)*) => {
        /// Usercall numbers from the official Fortanix ABI.
        #[allow(non_camel_case_types)]
        #[repr(u64)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Usercall {
            /// Zero denotes a library return, not a usercall.
            Invalid = 0,
            $($name,)*
        }
    };
}
fortanix_sgx_abi::invoke_with_usercalls!(usercall_numbers);

/// A call failed. After any call error (or handler panic), discard this caller.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The kernel does not provide the SGX vDSO entry point.
    MissingVdso,
    /// An earlier call failed or unwound while the enclave was suspended.
    Stopped,
    /// The vDSO reported a failure or an enclave CPU exception.
    Entry {
        code: i32,
        function: u32,
        vector: u16,
        error_code: u16,
        address: u64,
    },
    /// The enclave requested exit. The debug message is untrusted.
    Exit { panic: bool, message: String },
    /// No handler is installed for this synchronous usercall.
    UnsupportedUsercall(u64),
    /// An application-provided handler failed.
    Usercall(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingVdso => f.write_str("Linux SGX vDSO is unavailable"),
            Self::Stopped => f.write_str("caller stopped after an earlier failure"),
            Self::Entry {
                code,
                function,
                vector,
                error_code,
                address,
            } => write!(
                f,
                "SGX entry failed: code={code}, function={function}, exception={vector}, error={error_code}, address={address:#x}"
            ),
            Self::Exit { panic, message } => write!(f, "enclave exited (panic={panic}): {message}"),
            Self::UnsupportedUsercall(n) => write!(f, "unsupported usercall {n:#x}"),
            Self::Usercall(e) => write!(f, "usercall handler failed: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Usercall(e) => Some(e),
            _ => None,
        }
    }
}

/// An owned TCS, reusable for successive library calls.
///
/// `&mut self` prevents concurrent entry into the same TCS. Move a caller to
/// an existing worker, or protect it with a mutex. Different TCSes may have
/// separate callers; enclave-wide services and termination must then be
/// coordinated by the application. Ownership keeps the SGX mapping alive.
pub struct Caller<T: Tcs> {
    tcs: T,
    vdso: usize,
    stopped: bool,
}

impl<T: Tcs> Caller<T> {
    /// Takes ownership of an initialized library TCS. Resolves the vDSO once.
    pub fn new(tcs: T) -> Result<Self, Error> {
        Ok(Self {
            tcs,
            vdso: entry::vdso().ok_or(Error::MissingVdso)?,
            stopped: false,
        })
    }

    /// Calls a library entry point, using [`default_usercall`] for host services.
    ///
    /// # Safety
    /// The TCS must refer to a live enclave implementing the Fortanix library
    /// ABI, including preservation of the host stack and required CPU state.
    /// The enclave and arguments must uphold the host's memory safety: pointers,
    /// lengths, aliasing, and buffer lifetimes are application-defined. This
    /// is not a sandbox for malicious enclave code. An enclave must not retain
    /// borrowed host buffers after this method returns, including error returns.
    /// If any TCS exits/faults, the application must stop using all TCSes of
    /// that enclave. No async queues may be registered for this enclave.
    pub unsafe fn call(
        &mut self,
        p1: u64,
        p2: u64,
        p3: u64,
        p4: u64,
        p5: u64,
    ) -> Result<(u64, u64), Error> {
        unsafe { self.call_with([p1, p2, p3, p4, p5], default_usercall) }
    }

    /// Calls a library with an application-provided synchronous usercall handler.
    ///
    /// The handler receives the usercall number and four argument registers.
    /// It returns two result registers; unused registers must be zero. Exit is
    /// handled internally and never resumed. Each yield is handled exactly once.
    /// Handler errors and unwinding permanently stop this caller.
    ///
    /// # Safety
    /// All requirements of [`Self::call`] apply. The handler must validate
    /// usercall arguments before accessing host memory and keep any returned
    /// buffers alive for as long as the enclave can use them. It must not
    /// register async queues or re-enter this TCS. Shared services (e.g. memory
    /// allocation and wait/send) must have enclave-wide ownership and lifetimes.
    pub unsafe fn call_with(
        &mut self,
        mut registers: [u64; 5],
        mut handler: impl FnMut(u64, [u64; 4]) -> Result<(u64, u64), Error>,
    ) -> Result<(u64, u64), Error> {
        if self.stopped {
            return Err(Error::Stopped);
        }
        // Fail closed on both errors and Rust unwinding; never re-enter a
        // suspended usercall as if it were a fresh library invocation.
        self.stopped = true;
        let mut debug = [0u8; 1024];
        loop {
            let mut run = entry::Run {
                tcs: self.tcs.address() as u64,
                ..Default::default()
            };
            let code =
                unsafe { entry::enter(self.vdso, &mut registers, debug.as_mut_ptr(), &mut run) };
            if code != 0 || run.function != 4 {
                // EEXIT
                return Err(Error::Entry {
                    code,
                    function: run.function,
                    vector: run.exception_vector,
                    error_code: run.exception_error_code,
                    address: run.exception_addr,
                });
            }
            match registers[0] {
                0 => {
                    self.stopped = false;
                    return Ok((registers[1], registers[2]));
                }
                n if n == Usercall::exit as u64 => {
                    let message = debug.split(|b| *b == 0).next().unwrap();
                    return Err(Error::Exit {
                        panic: registers[1] != 0,
                        message: String::from_utf8_lossy(message).into_owned(),
                    });
                }
                n => {
                    let (a, b) =
                        handler(n, [registers[1], registers[2], registers[3], registers[4]])?;
                    // Zero selects the usercall continuation, not a new call.
                    registers = [0, a, b, 0, 0];
                }
            }
        }
    }
}

/// Minimal host services, usable as the fallback in a custom handler.
///
/// Supports `insecure_time` (without a cached clock pointer). `launch_thread`
/// and `async_queues` return ABI errors. Other usercalls stop the caller with
/// [`Error::UnsupportedUsercall`]. In particular, allocation, I/O, and wait/send
/// require application handlers; this is not a replacement for the full runner.
pub fn default_usercall(number: u64, _args: [u64; 4]) -> Result<(u64, u64), Error> {
    if number == Usercall::insecure_time as u64 {
        let ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::Usercall(std::io::Error::other(e)))?
            .as_nanos();
        Ok((ns.min(u64::MAX as u128) as u64, 0))
    } else if number == Usercall::launch_thread as u64 || number == Usercall::async_queues as u64 {
        Ok((fortanix_sgx_abi::Error::Other as u64, 0))
    } else {
        Err(Error::UnsupportedUsercall(number))
    }
}

#[cfg(test)]
mod tests;
