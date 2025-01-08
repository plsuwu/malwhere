use windows::{core::{PCSTR, PCWSTR}, Win32::Foundation::HANDLE};

const SEED_INIT: u32 = 8;

pub struct JenkinsOATHash {
    pub plain: String,
    pub hash: u32,
}

impl JenkinsOATHash {

    // "main" hashing function; other methods below simply convert their params to
    // a `&str` type and call this method; this function is basically 1:1 from a C
    // implementation
    // (https://en.wikipedia.org/wiki/Jenkins_hash_function)
    pub fn from_str(input: &str) -> Self {
        let mut hash: u32 = 0;
        
        for byte in input.bytes() {
            hash = hash.wrapping_add(byte as u32);
            hash = hash.wrapping_add(hash.wrapping_shl(SEED_INIT));
            hash ^= hash >> 6;
        }
    
        hash = hash.wrapping_add(hash.wrapping_shl(3));
        hash ^= hash >> 11;
        hash = hash.wrapping_add(hash.wrapping_shl(15));
    
        JenkinsOATHash {
            plain: input.to_string(),
            hash,
        }
    }

    // idk if the impl functions below actually work but i cant see why
    // they wouldn't, right (??)
    pub fn from_pcstr(input: PCSTR) -> Self {
        let input_str = unsafe {
            match input.to_string() {
                Ok(val) => val,
                Err(_) => {
                    panic!();
                }
            }
        };

        return Self::from_str(&input_str);
    }

    pub fn from_pcwstr(input: PCWSTR) -> Self {
        let input_str = unsafe {
            match input.to_string() {
                Ok(val) => val,
                Err(_) => {
                    panic!();
                }
            }
        };

        return Self::from_str(&input_str);
    }
}

pub struct RemoteProcHandle {
    pub pid: u32,
    pub process: HANDLE,
}

pub unsafe fn vx_move_memory(
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