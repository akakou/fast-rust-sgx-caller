use super::*;
use std::arch::naked_asm;
use std::ffi::c_void;

#[derive(Debug)]
struct TestTcs;
impl Tcs for TestTcs {
    fn address(&self) -> *mut c_void {
        std::ptr::null_mut()
    }
}

// Substitute only the vDSO, exercising the actual assembly bridge and call
// state machine on hosts without SGX. Deliberately clobber R12-R15 as AEX can.
#[unsafe(naked)]
unsafe extern "C" fn fake_vdso() {
    naked_asm!(
        "mov rax, [rsp + 8]",
        "mov dword ptr [rax + 8], 4",
        "mov r12, -1", "mov r13, -1", "mov r14, -1", "mov r15, -1",
        "cmp rdi, 2", "je 2f",
        "cmp rdi, 3", "je 3f",
        "cmp rdi, 4", "je 4f",
        // For both ordinary entry and resume, fold all four arguments.
        "add rsi, r8", "add rdx, r9", "xor edi, edi", "jmp 5f",
        "2:", "mov rdi, rsi", "mov rsi, rdx", "mov rdx, r8",
        "mov r8, r9", "xor r9d, r9d", "jmp 5f",
        "3:", "mov word ptr [r10], 0x0058", "mov edi, {exit}", "mov esi, 1", "jmp 5f",
        "4:", "mov dword ptr [rax + 8], 3", "mov word ptr [rax + 12], 6",
        "5:", "xor eax, eax", "ret",
        exit = const Usercall::exit as u64,
    );
}

fn caller() -> Caller<TestTcs> {
    Caller {
        tcs: TestTcs,
        vdso: fake_vdso as *const () as usize,
        stopped: false,
    }
}

#[test]
fn bridge_and_continuation() {
    let mut caller = caller();
    for i in 0..100 {
        assert_eq!(unsafe { caller.call(1, i, 2, 3, 4).unwrap() }, (i + 3, 6));
    }
    let mut calls = 0;
    assert_eq!(
        unsafe {
            caller
                .call_with([2, 123, 10, 20, 30], |n, args| {
                    calls += 1;
                    assert_eq!(n, 123);
                    assert_eq!(args, [10, 20, 30, 0]);
                    Ok((99, 101))
                })
                .unwrap()
        },
        (99, 101)
    );
    assert_eq!(calls, 1);
    assert_eq!(unsafe { caller.call(1, 1, 2, 3, 4).unwrap() }, (4, 6));
}

#[test]
fn failure_and_unwind_never_reenter() {
    for op in [2, 3, 4] {
        let mut caller = caller();
        let error = unsafe { caller.call(op, 123, 0, 0, 0).unwrap_err() };
        match op {
            2 => assert!(matches!(error, Error::UnsupportedUsercall(123))),
            3 => assert!(matches!(error, Error::Exit { panic: true, message } if message == "X")),
            4 => assert!(matches!(error, Error::Entry { vector: 6, .. })),
            _ => unreachable!(),
        }
        assert!(matches!(
            unsafe { caller.call(1, 0, 0, 0, 0) },
            Err(Error::Stopped)
        ));
    }
    let mut caller = caller();
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        caller.call_with([2, 123, 0, 0, 0], |_, _| panic!("handler panic"))
    }));
    assert!(unwind.is_err());
    assert!(matches!(
        unsafe { caller.call(1, 0, 0, 0, 0) },
        Err(Error::Stopped)
    ));
}

#[test]
fn default_services() {
    let (time, pointer) = default_usercall(Usercall::insecure_time as u64, [0; 4]).unwrap();
    assert!(time > 0);
    assert_eq!(pointer, 0);
    for n in [Usercall::async_queues, Usercall::launch_thread] {
        let (error, unused) = default_usercall(n as u64, [0; 4]).unwrap();
        assert_ne!(error, 0);
        assert_eq!(unused, 0);
    }
    assert!(matches!(
        default_usercall(u64::MAX, [0; 4]),
        Err(Error::UnsupportedUsercall(u64::MAX))
    ));
}
