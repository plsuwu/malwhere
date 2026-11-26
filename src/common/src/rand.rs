use core::arch::x86_64::{__cpuid, _rdrand64_step};

use crate::winapi::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, SYSTEM_PREFERRED_ALG_HANDLE};
use crate::winapi::{BCryptGenRandom, LARGE_INTEGER, QueryPerformanceCounter};

pub fn random_seed() -> u64 {
    #[cfg(target_arch = "x86_64")]
    if let Some(v) = rdrand64() {
        return v;
    }

    #[cfg(windows)]
    if let Some(v) = bcrypt_u64() {
        return v;
    }

    // something vaguely random-like as a final best-effort fallback
    query_counter()
}

fn has_rdrand() -> bool {
    (__cpuid(1).ecx >> 30) & 1 == 1
}

#[target_feature(enable = "rdrand")]
unsafe fn rdrand64_raw() -> Option<u64> {
    for _ in 0..10 {
        let mut v = 0u64;
        if _rdrand64_step(&mut v) == 1 && v != 0 && v != u64::MAX {
            return Some(v);
        }
    }

    None
}

pub fn query_counter() -> u64 {
    let mut ctr = LARGE_INTEGER::default();
    let _ = unsafe { QueryPerformanceCounter(&mut ctr) };

    unsafe { ctr.QuadPart }.cast_unsigned()
}

fn bcrypt_u64() -> Option<u64> {
    let mut buf = [0u8; 8];
    let status = unsafe {
        BCryptGenRandom(
            SYSTEM_PREFERRED_ALG_HANDLE,
            buf.as_mut_ptr(),
            buf.len() as _,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };

    (status >= 0).then(|| u64::from_le_bytes(buf))
}

fn rdrand64() -> Option<u64> {
    if has_rdrand() {
        unsafe { rdrand64_raw() }
    } else {
        None
    }
}
