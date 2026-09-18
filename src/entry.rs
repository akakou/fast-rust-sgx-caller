//! Linux vDSO boundary. The enclave must implement the Fortanix calling convention.
use std::arch::naked_asm;
use std::sync::OnceLock;

#[repr(C)]
#[derive(Default, Debug)]
pub(crate) struct Run {
    pub tcs: u64,
    pub function: u32,
    pub exception_vector: u16,
    pub exception_error_code: u16,
    pub exception_addr: u64,
    pub(crate) user_handler: u64,
    pub(crate) user_data: u64,
    pub(crate) reserved: [u64; 27],
}

pub(crate) fn vdso() -> Option<usize> {
    static ENTRY: OnceLock<Option<usize>> = OnceLock::new();
    *ENTRY.get_or_init(|| unsafe {
        let handle = libc::dlopen(
            c"linux-vdso.so.1".as_ptr(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        if handle.is_null() {
            return None;
        }
        let symbol = libc::dlsym(handle, c"__vdso_sgx_enter_enclave".as_ptr());
        // The kernel-provided vDSO remains mapped for the process's lifetime.
        libc::dlclose(handle);
        (!symbol.is_null()).then_some(symbol as usize)
    })
}

// A normal C call is insufficient: RDI/RSI/RDX/R8/R9 are both inputs and
// outputs, R10 carries the debug buffer, and AEX may clobber R12-R15.
// This wrapper saves all SysV callee-saved registers. The extern C boundary
// also tells rustc that caller-saved registers (including SIMD) are clobbered.
// RBP and RSP must be preserved by the enclave, as required by the vDSO ABI.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn enter(
    vdso: usize,
    registers: *mut [u64; 5],
    debug: *mut u8,
    run: *mut Run,
) -> i32 {
    naked_asm!(
        "push rbp",
        "push rbx",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        // Align RSP to 16 bytes before CALL. The seventh vDSO argument is
        // on the stack; keep the register-array pointer beyond that argument.
        "sub rsp, 24",
        "mov [rsp], rcx",
        "mov [rsp + 8], rsi",
        "mov r11, rdi",
        "mov r10, rdx",
        "mov rdi, [rsi]",
        "mov rdx, [rsi + 16]",
        "mov r8, [rsi + 24]",
        "mov r9, [rsi + 32]",
        "mov rsi, [rsi + 8]",
        "mov ecx, 2", // EENTER; the vDSO handles asynchronous ERESUME.
        "call r11",
        "mov r11, [rsp + 8]",
        "mov [r11], rdi",
        "mov [r11 + 8], rsi",
        "mov [r11 + 16], rdx",
        "mov [r11 + 24], r8",
        "mov [r11 + 32], r9",
        "add rsp, 24",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbx",
        "pop rbp",
        "ret",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_layout() {
        assert_eq!(std::mem::size_of::<Run>(), 256);
        assert_eq!(std::mem::offset_of!(Run, function), 8);
        assert_eq!(std::mem::offset_of!(Run, exception_addr), 16);
        assert_eq!(std::mem::offset_of!(Run, user_handler), 24);
        assert_eq!(std::mem::offset_of!(Run, reserved), 40);
    }
}
