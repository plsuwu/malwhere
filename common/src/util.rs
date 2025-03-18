#![allow(dead_code)]
#![allow(unused)]

use crate::environment_block::read_gs::{GetBlock, __readgsqword};
use crate::environment_block::types::PROCESS_ENVIRONMENT_BLOCK as PEB;
use alloc::ffi::CString;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use anyhow::Result;
use core::ffi::c_void;
use core::mem::size_of;
use core::slice::from_raw_parts;
use libc_print::{libc_dbg, libc_println};
use libc_print::std_name::println;

pub unsafe fn move_memory(dest: *mut c_void, src: *const c_void, len: usize) -> *const c_void {
    let d: *mut usize = dest.cast();
    let s: *const usize = src.cast();

    // handle word-aligned copies first
    let words = len / size_of::<usize>();
    let remainder = len % size_of::<usize>();

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

    dest
}

pub unsafe fn get_cmd_line() -> String {
    let peb = PEB::get();
    (*peb.ProcessParameters).CommandLine.Buffer.to_string().unwrap()
}


pub unsafe fn get_current_dir() -> String {
    let peb = PEB::get();
    (*peb.ProcessParameters).CurrentDirectory.DosPath.Buffer.to_string().unwrap()
}

pub unsafe fn get_current_process_id() -> u64 {
    __readgsqword(0x40)
}

pub unsafe fn get_current_thread_id() -> u64 {
    __readgsqword(0x48)
}

pub unsafe fn search_env(needle: Option<&str>) -> Vec<String> {
    let peb = PEB::get();

    let env_ptr = (*peb.ProcessParameters).Environment;
    let mut vars = Vec::new();
    let mut offset = 0;

    loop {
        let mut var_len = 0;
        while *env_ptr.add(offset + var_len) != 0 {
            var_len += 1;
        }

        if var_len == 0 {
            break;
        }

        let mut var_string =
            String::from_utf16(from_raw_parts(env_ptr.add(offset), var_len)).unwrap();

        if needle.is_some() {
            if var_string.starts_with(needle.unwrap()) {
                let res = var_string
                    .split('=')
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()[1]
                    .clone();

                vars.push(res);
                return vars;
            }
        } else {
            vars.push(var_string);
        }

        offset += var_len + 1;
    }

    vars
}
