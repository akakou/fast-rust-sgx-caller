//! Minimal real Rust std library-mode enclave for the smoke test.
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

static STATE: OnceLock<Mutex<u64>> = OnceLock::new();

#[unsafe(no_mangle)]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn entry(op: u64, a: u64, b: u64, _: u64, c: u64, d: u64) -> (u64, u64) {
    match op {
        1 => {
            let mut state = STATE.get_or_init(|| Mutex::new(0)).lock().unwrap();
            *state += 1;
            // Exercise the enclave allocator, and std initialization/state.
            let mut values = Vec::with_capacity(4);
            values.extend_from_slice(&[a, b, c, d]);
            let sum = std::hint::black_box(values)
                .into_iter()
                .fold(0u64, u64::wrapping_add);
            (sum, *state)
        }
        2 => (
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
            0,
        ),
        _ => (u64::MAX, 0),
    }
}

fn main() {}
