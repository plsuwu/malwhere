use core::cell::{LazyCell, UnsafeCell};
use core::ffi::c_void;
use core::hint;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use common::hashing::DEFAULT_KEY;
use common::widehash;

use crate::syscall::{_NtAlertThreadByThreadId, _NtWaitForAlertByThreadId, NtSyscall};

pub const STATUS_ALERTED: i32 = 0x0000_0101;
pub const STATUS_TIMEOUT: i32 = 0x0000_0102;

static mut SYNC_SC: LazyCell<[NtSyscall; 2]> = LazyCell::new(|| {
    [
        NtSyscall::new(widehash!("NtWaitForAlertByThreadId\0", &DEFAULT_KEY)),
        NtSyscall::new(widehash!("NtAlertThreadByThreadId\0", &DEFAULT_KEY)),
    ]
});

#[inline]
fn wait_sc() -> NtSyscall {
    unsafe { SYNC_SC[0] }
}

#[inline]
fn alert_sc() -> NtSyscall {
    unsafe { SYNC_SC[1] }
}

const UNLOCKED: u32 = 0;
const LOCKED: u32 = 1;

pub struct MutexGuard<'a, T> {
    lock: &'a Mutex<T>,
}

impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.unlock();
    }
}

pub struct Mutex<T> {
    state: AtomicU32,
    sleeper: AtomicUsize,
    value: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for Mutex<T> {}
unsafe impl<T: Sync> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    pub const fn new(val: T) -> Self {
        Self {
            state: AtomicU32::new(UNLOCKED),
            sleeper: AtomicUsize::new(0),
            value: UnsafeCell::new(val),
        }
    }

    #[inline]
    pub fn lock(&self) -> MutexGuard<'_, T> {
        // fast path
        if self
            .state
            .compare_exchange(UNLOCKED, LOCKED, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return MutexGuard { lock: self };
        }

        self.lock_slow();
        MutexGuard { lock: self }
    }

    #[cold]
    fn lock_slow(&self) {
        let tid = super::current_thread_id();
        loop {
            if self
                .state
                .compare_exchange(UNLOCKED, LOCKED, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }

            if self
                .sleeper
                .compare_exchange(0, tid, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                if self
                    .state
                    .compare_exchange(UNLOCKED, LOCKED, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    let _ =
                        self.sleeper
                            .compare_exchange(tid, 0, Ordering::SeqCst, Ordering::Relaxed);
                    return;
                }
                let _ = unsafe {
                    _NtWaitForAlertByThreadId(
                        &wait_sc(),
                        &self.state as *const _ as *mut c_void,
                        core::ptr::null(), // no timeout
                    )
                };

                let _ = self
                    .sleeper
                    .compare_exchange(tid, 0, Ordering::SeqCst, Ordering::Relaxed);
            } else {
                // another thread owns the parking lot, so we progress by spinning
                hint::spin_loop();
            }
        }
    }

    #[inline]
    fn unlock(&self) {
        self.state.swap(UNLOCKED, Ordering::SeqCst);

        let tid = self.sleeper.swap(0, Ordering::SeqCst);
        if tid != 0 {
            unsafe { _NtAlertThreadByThreadId(&alert_sc(), tid as u32) };
        }
    }
}
