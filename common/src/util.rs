pub unsafe fn move_memory(
    dest: *mut std::ffi::c_void,
    src: *const std::ffi::c_void,
    len: usize,
) -> *const std::ffi::c_void {

    let d: *mut usize = dest.cast();
    let s: *const usize = src.cast();

    // handle word-aligned copies first
    let words = len / std::mem::size_of::<usize>();
    let remainder = len % std::mem::size_of::<usize>();

    // forward-copy
    if d < s as *mut usize {

        // handle word-aligned first
        for i in 0..words {
            *d.add(i) = *(s.add(i));
        }

        let d_tail: *mut u8 = d.add(words).cast();
        let s_tail: *const u8 = s.add(words).cast();
        for i in 0..remainder {
            *d_tail.add(i) = *s_tail.add(i);
        }

    // reverse-copy
    } else {
        for i in (0..words).rev() {
            *d.add(i) = *(s.add(i));
        }

        let d_tail: *mut u8 = d.add(words).cast();
        let s_tail: *const u8 = s.add(words).cast();
        for i in (0..remainder).rev() {
            *d_tail.add(i) = *s_tail.add(i);
        }
    }

    return dest;
}