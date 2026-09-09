extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

const DEFAULT_PAGE_SIZE: usize = 4096;
static PAGE_SIZE: AtomicUsize = AtomicUsize::new(0);

/// `GlobalAlloc` via Linux `mmap`/`munmap`/`mremap` syscalls
#[global_allocator]
pub static ALLOCATOR: LinuxHeap = LinuxHeap(Libc);

/// Determine and cache system page size via `sysconf` call, using
/// `DEFAULT_PAGE_SIZE` as a default fallback value if this call fails
fn page_size() -> usize {
    let cached = PAGE_SIZE.load(Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }

    let ps = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) };
    let ps = if ps > 0 {
        ps as usize
    } else {
        DEFAULT_PAGE_SIZE
    };

    PAGE_SIZE.store(ps, Ordering::Relaxed);
    ps
}

/// Round `n` up to a multiple of `to`
#[inline]
fn round_up(n: usize, to: usize) -> Option<usize> {
    n.checked_add(to - 1).map(|x| x & !(to - 1))
}

/// `mmap` allocation of `len` bytes and return the base address of the allocation.
///
/// Returns `core::ptr::null_mut()` on failure.
///
/// # Flags
///
/// - protections: `PROT_READ | PROT_WRITE`
/// - visibility: `MAP_PRIVATE | MAP_ANONYMOUS`
unsafe fn map(len: usize) -> *mut u8 {
    let p = unsafe {
        libc::mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };

    if p == libc::MAP_FAILED {
        ptr::null_mut()
    } else {
        p as *mut u8
    }
}

pub trait Mapper {
    fn page_size(&self) -> usize;
    unsafe fn map(&self, len: usize) -> *mut u8;
    unsafe fn unmap(&self, ptr: *mut u8, len: usize);
    unsafe fn remap(&self, ptr: *mut u8, old: usize, new: usize) -> *mut u8;
}

pub struct Libc;

impl Mapper for Libc {
    fn page_size(&self) -> usize {
        page_size()
    }

    unsafe fn map(&self, len: usize) -> *mut u8 {
        unsafe { map(len) }
    }

    unsafe fn unmap(&self, ptr: *mut u8, len: usize) {
        unsafe {
            libc::munmap(ptr as *mut _, len);
        }
    }

    /// delegates remapping move/grow to the kernel if possible
    unsafe fn remap(&self, ptr: *mut u8, old: usize, new: usize) -> *mut u8 {
        let p = unsafe { libc::mremap(ptr as *mut _, old, new, libc::MREMAP_MAYMOVE) };
        if p == libc::MAP_FAILED {
            ptr::null_mut()
        } else {
            p as *mut u8
        }
    }
}

pub struct LinuxHeap<M: Mapper = Libc>(pub M);

unsafe impl<M: Mapper> GlobalAlloc for LinuxHeap<M> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ps = self.0.page_size();
        let size = match round_up(layout.size(), ps) {
            Some(s) => s,
            None => return ptr::null_mut(),
        };
        let align = layout.align();

        // NOTE: mmap always returns page-aligned results
        if align <= ps {
            return unsafe { self.0.map(size) };
        }

        // trim over-aligned allocations by mapping `size + align` and then unmapping unaligned
        // head/tail; partial `munmap` should be legal here as both slices are multiples of
        // `PAGE_SIZE`.
        let total = match size.checked_add(align) {
            Some(t) => t,
            None => return ptr::null_mut(),
        };

        let base = unsafe { self.0.map(total) };
        if base.is_null() {
            return base;
        }
        let start = base as usize;
        let aligned = (start + align - 1) & !(align - 1);
        let head = aligned - start;
        let tail = total - head - size;
        if head != 0 {
            unsafe { self.0.unmap(base as *mut _, head) };
        }
        if tail != 0 {
            unsafe { self.0.unmap((aligned + size) as *mut _, tail) };
        }

        aligned as *mut u8
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let ps = self.0.page_size();
        let old = unsafe { round_up(layout.size(), ps).unwrap_unchecked() };
        let new = match round_up(new_size, ps) {
            Some(n) => n,
            None => return ptr::null_mut(),
        };
        if old == new {
            return ptr;
        }

        if layout.align() <= ps {
            return unsafe { self.0.remap(ptr as *mut _, old, new) };
        }

        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        let np = unsafe { self.alloc(new_layout) };
        if !np.is_null() {
            unsafe {
                ptr::copy_nonoverlapping(ptr, np, core::cmp::min(layout.size(), new_size));
                self.dealloc(ptr, layout);
            }
        }

        np
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // this probably shouldn't overflow (smile)
        let size = unsafe { round_up(layout.size(), page_size()).unwrap_unchecked() };
        unsafe { self.0.unmap(ptr as *mut _, size) };
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { self.alloc(layout) }
    }
}

/// 12 trillion tests lmao
/// > NOTE: Mock system memory allocator implements `Mapper` after the tests.
#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use std::boxed::Box;
    use std::string::String;
    use std::vec::Vec;

    use core::alloc::GlobalAlloc;
    use std::alloc::Layout;
    use std::collections::BTreeMap;
    use std::sync::{Mutex, atomic::AtomicBool};

    const PS: usize = 4096;

    #[test]
    fn alignment_and_trimming_are_exact() {
        for align in [1, 8, PS, PS * 2, PS * 16, 1 << 20] {
            for size in [1, PS - 1, align, align * 3 + 17] {
                let a = LinuxHeap(Fake::default());
                let l = layout(size, align);
                unsafe {
                    let p = a.alloc(l);
                    assert!(!p.is_null());
                    assert_eq!(p as usize % align, 0);

                    assert_eq!(a.0.live_bytes(), up(size), "size={size} align={align}");
                    assert!(a.0.is_mapped(p, size));
                    ptr::write_bytes(p, 0xab, size);
                    a.dealloc(p, l);
                    assert_eq!(a.0.live_bytes(), 0);
                }
            }
        }
    }

    #[test]
    fn realloc_preserves_data_and_leaks_nothing() {
        for align in [8, PS * 4] {
            let a = LinuxHeap(Fake::default());
            let mut l = layout(PS, align);
            unsafe {
                let mut p = a.alloc(l);
                for i in 0..l.size() {
                    *p.add(i) = (i % 251) as u8;
                }
                for new in [PS * 10, PS * 3, 100, PS * 40] {
                    let keep = new.min(l.size());
                    let np = a.realloc(p, l, new);
                    assert!(!np.is_null());
                    assert_eq!(np as usize % align, 0);

                    for i in 0..keep {
                        assert_eq!(*np.add(i), (i % 251) as u8);
                    }
                    for i in keep..new {
                        *np.add(i) = (i % 251) as u8;
                    }

                    assert_eq!(a.0.live_bytes(), up(new));
                    p = np;
                    l = layout(new, align);
                }
                a.dealloc(p, l);
                assert_eq!(a.0.live_bytes(), 0);
            }
        }
    }

    #[test]
    fn map_failure_propagates_as_null_without_leaks() {
        let a = LinuxHeap(Fake::default());
        for align in [8, PS * 8] {
            a.0.fail_next();
            unsafe { assert!(a.alloc(layout(100, align)).is_null()) };
            assert_eq!(a.0.live_bytes(), 0);
        }

        let l = layout(PS, 8);
        unsafe {
            let p = a.alloc(l);
            *p = 42;
            a.0.fail_next();
            assert!(a.realloc(p, l, PS * 4).is_null());
            assert!(a.0.is_mapped(p, PS));
            assert_eq!(*p, 42);
            a.dealloc(p, l);
        }
    }

    #[test]
    fn huge_valid_layouts_return_null_without_leaks() {
        let a = LinuxHeap(Fake::default());
        let huge = isize::MAX as usize - PS;
        unsafe {
            assert!(a.alloc(layout(huge, 8)).is_null());
            assert!(a.alloc(layout(1 << 62, 1 << 62)).is_null());
            let l = layout(PS, 8);
            let p = a.alloc(l);
            *p = 42;
            assert!(a.realloc(p, l, huge).is_null());
            assert!(a.0.is_mapped(p, PS));
            assert_eq!(*p, 42);
            a.dealloc(p, l);
        }
        assert_eq!(a.0.live_bytes(), 0);
    }

    #[test]
    fn libc_impl() {
        let mut v: Vec<u64> = Vec::new();
        for i in 0..100_000 {
            v.push(i);
        }
        assert_eq!(v.iter().sum::<u64>(), 4_999_950_000);
        let mut s: String = String::new();
        for c in ["f", "o", "o", " ", "b", "a", "r", " ", "b", "a", "z"] {
            s.push_str(c);
        }
        assert_eq!(&s, "foo bar baz");
        let b: Vec<Box<[u8; 4096]>> = (0..64).map(|_| Box::new([7u8; 4096])).collect();
        assert!(b.iter().all(|x| x[4095] == 7));
    }

    struct Fake {
        live: Mutex<BTreeMap<usize, usize>>,
        backing: Mutex<Vec<(usize, Layout)>>,
        fail_next: AtomicBool,
        capacity: usize,
    }

    impl Default for Fake {
        fn default() -> Self {
            Self {
                live: Default::default(),
                backing: Default::default(),
                fail_next: Default::default(),
                capacity: 1 << 30,
            }
        }
    }

    impl Fake {
        fn live_bytes(&self) -> usize {
            self.live.lock().unwrap().values().sum()
        }
        fn is_mapped(&self, p: *mut u8, len: usize) -> bool {
            let p = p as usize;
            self.live
                .lock()
                .unwrap()
                .range(..=p)
                .next_back()
                .is_some_and(|(&s, &l)| p + len <= s + l)
        }
        fn fail_next(&self) {
            self.fail_next.store(true, Ordering::SeqCst);
        }
    }

    impl Mapper for Fake {
        fn page_size(&self) -> usize {
            PS
        }
        unsafe fn map(&self, len: usize) -> *mut u8 {
            assert_eq!(len % PS, 0, "map len not a page multiple");
            if self.fail_next.swap(false, Ordering::SeqCst) {
                return ptr::null_mut();
            }
            if len > self.capacity {
                return ptr::null_mut();
            }
            let l = Layout::from_size_align(len, PS).unwrap();
            let p = unsafe { std::alloc::alloc_zeroed(l) };
            assert!(!p.is_null());
            self.backing.lock().unwrap().push((p as usize, l));
            self.live.lock().unwrap().insert(p as usize, len);
            p
        }
        unsafe fn unmap(&self, ptr: *mut u8, len: usize) {
            let p = ptr as usize;
            assert_eq!(p % PS, 0, "unmap addr should be page-aligned");
            assert_eq!(len % PS, 0, "unmap len should be a multiple of page size");
            let mut live = self.live.lock().unwrap();
            let (&start, &rlen) = live
                .range(..=p)
                .next_back()
                .expect("tried to unmap addr that was not mapped");
            assert!(p + len <= start + rlen, "unmap runs past end of mapping");
            live.remove(&start);
            if p > start {
                live.insert(start, p - start);
            }
            if p + len < start + rlen {
                live.insert(p + len, start + rlen - p - len);
            }
        }
        unsafe fn remap(&self, ptr: *mut u8, old: usize, new: usize) -> *mut u8 {
            assert!(self.is_mapped(ptr, old), "remap of unmapped range");
            let np = unsafe { self.map(new) };
            if np.is_null() {
                return np;
            }
            unsafe {
                ptr::copy_nonoverlapping(ptr, np, old.min(new));
                self.unmap(ptr, old);
            }
            np
        }
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            for &(p, l) in self.backing.lock().unwrap().iter() {
                unsafe { std::alloc::dealloc(p as *mut u8, l) };
            }
        }
    }

    const fn up(n: usize) -> usize {
        (n + PS - 1) & !(PS - 1)
    }
    fn layout(size: usize, align: usize) -> Layout {
        Layout::from_size_align(size, align).unwrap()
    }
}
