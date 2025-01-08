// NOTE:
// tragically, building this with the release profile applies some optimization or something that
// breaks the part where we do hooking things
// for now just `cargo build --debug` or whatever i'm begging you

use core::{ffi::c_void, ptr::null_mut};

use windows::{
    core::{PCSTR, PCWSTR},
    Win32::{
        Foundation::{GetLastError, HWND},
        System::Memory::{
            VirtualProtect, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
        },
        UI::WindowsAndMessaging::{
            MessageBoxA, MessageBoxW, MB_OK, MESSAGEBOX_RESULT, MESSAGEBOX_STYLE,
        },
    },
};

// `MessageBoxA` function prototype
type MbFunction = unsafe fn(HWND, PCSTR, PCSTR, MESSAGEBOX_STYLE) -> MESSAGEBOX_RESULT;

// shellcode trampoline hook
// copy a function address into r10 then unconditional jump to
// that address:
// ```
// mov r10, <address>
// jmp r10
// ```
const X64_TRAMPOLINE: [u8; 13] = [
    0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xE2,
];

// `Hook` struct to track function addresses and the original memory contents so we can
// unhook ourselves when required
#[derive(Debug)]
struct Hook {
    p_target: *const u64,
    p_replace: *const u64,
    original_bytes: [u8; 13],
    prev_protect: *mut PAGE_PROTECTION_FLAGS,
}

impl Hook {
    // create a new instance of a hook at the base address of an API function
    unsafe fn new(p_target: *const c_void, p_replace: *const c_void) -> Self {
        // bind the array of bytes and protection fields with zeroed data
        let mut original_bytes: [u8; 13] = Default::default(); // 0x0
        let prev_protect: *mut PAGE_PROTECTION_FLAGS = &mut PAGE_PROTECTION_FLAGS::default(); // PAGE_PROTECTION_FLAGS(0) (?)

        // copy original memory into our struct so we can unhook later
        std::ptr::copy(
            p_target as *mut u8,
            original_bytes.as_mut_ptr() as *mut u8,
            X64_TRAMPOLINE.len(),
        );

        // create a backup of this regions protections and set to `PAGE_EXECUTE_READWRITE`
        // must set RWX here as the instructions we need to execute aren't permitted on RX-only memory
        let new_protect = VirtualProtect(
            p_target as *const c_void,
            X64_TRAMPOLINE.len(),
            PAGE_EXECUTE_READWRITE,
            prev_protect,
        );

        if new_protect.is_err() {
            println!("[x] VirtualProtect (RWX) FAIL: Err '{:?}'", GetLastError());
            return Self {
                p_target: null_mut(),
                p_replace: null_mut(),
                original_bytes,
                prev_protect,
            };
        }

        return Self {
            p_target: p_target as *const u64,
            p_replace: p_replace as *const u64,
            original_bytes,
            prev_protect,
        };
    }

    // copy our function into the null-byte section of our trampoline base,
    // and then copy the trampoline with our function address into the base address of
    // the target function
    unsafe fn install(&self) {
        println!("[+] hooking function `0x{:016X?}'", self.p_target);

        // clone immutable trampoline const and offset pointer
        // by 2 bytes to overwrite null bytes of trampoline
        let mut trampoline_clone = X64_TRAMPOLINE.clone();
        let u_trampoline = trampoline_clone.as_mut_ptr().add(2);

        // cast the our function's address as a u64 so we are able to copy a
        // reference to the function pointer address itself (which we must then cast as a *const u8 to match the
        // trampoline ptr type) into the 8 null bytes of the trampoline to create the `mov r10, <address>`
        // instruction
        let addr = self.p_replace as u64;
        std::ptr::copy(
            &addr as *const u64 as *const u8,
            u_trampoline,
            std::mem::size_of::<u64>(),
        );

        // copy the instruction into the memory region occupied by the API function
        std::ptr::copy(
            trampoline_clone.as_ptr() as *const u8,
            self.p_target as *mut u8,
            X64_TRAMPOLINE.len(),
        );

        println!("[+] hook applied ok:");
        println!("[ ]\tmov r10, [0x{:016x?}h]\n", addr);
        return;
    }

    unsafe fn uninstall(&mut self) {
        println!("\n[+] unhooking function: `{:?}'", self.p_target);

        // this is basically the installation but we don't need to worry about creating the
        // shellcode `mov` instruction
        let prev_protect = self.prev_protect.clone();
        let p_original = self.original_bytes.as_mut_ptr() as *const u8;

        std::ptr::copy(p_original, self.p_target as *mut u8, X64_TRAMPOLINE.len());

        // reset the page's memory protections
        let _ = VirtualProtect(
            self.p_target as *const c_void,
            X64_TRAMPOLINE.len(),
            *prev_protect,
            null_mut(),
        );
        println!("[+] unhooked function ok");

        // zero all pointers and variables to clean up potential indicators
        self.original_bytes = Default::default();
        self.p_target = std::ptr::null();
        self.p_replace = std::ptr::null();
        self.prev_protect = std::ptr::null_mut() as *mut PAGE_PROTECTION_FLAGS;
        println!("[+] pointer cleanup ok");

        return;
    }
}

// this function will need to be reimplemented if we want to do something other than evil message
unsafe fn example_hook(
    h_wnd: HWND,
    pprev_msg: PCSTR,
    pprev_caption: PCSTR,
    _prev_style: MESSAGEBOX_STYLE,
) -> MESSAGEBOX_RESULT {
    let p_caption = "evil evil evil evil evil e\0"
        .encode_utf16()
        .collect::<Vec<_>>()
        .as_ptr();
    let p_message = "WOE BE UPON YE\0"
        .encode_utf16()
        .collect::<Vec<_>>()
        .as_ptr();

    println!("[+] recv API call `MessageBoxA`:");
    println!(
        "[+]\t-hwnd:\t {:?}\n[+]\t-msg:\t {:X?}\n[+]\t-capt:\t {:X?}",
        h_wnd,
        pprev_msg.to_string(),
        pprev_caption.to_string()
    );

    // we need to supply the same return type as would be expected from `MessageBoxA`;
    // i couldn't figure out how to clone the API function like we could do in C, so im just
    // returning the default MESSAGEBOX_RESULT but calling `MessageBoxW` because the POC
    // is easy to understand
    let _hookbox = MessageBoxW(
        h_wnd,
        PCWSTR::from_raw(p_message),
        PCWSTR::from_raw(p_caption),
        MB_OK,
    );

    return MESSAGEBOX_RESULT::default();
}

fn main() {
    let h_wnd: HWND = HWND::default();
    let p_message: PCSTR = PCSTR::from_raw("omg hiii\0".as_ptr());
    let p_caption: PCSTR = PCSTR::from_raw("oh my god\0".as_ptr());
    unsafe {
        // create constant ptr to a u64 from a function address via type transmutation
        let p_message_box_a: *const u64 = std::mem::transmute(MessageBoxA as MbFunction);
        let p_replacement_fn: *const u64 = std::mem::transmute(example_hook as MbFunction);

        let mut h = Hook::new(
            p_message_box_a as *const c_void,
            p_replacement_fn as *const c_void,
        );

        println!("{:#?}", h);

        MessageBoxA(h_wnd, p_message, p_caption, MB_OK);

        h.install();
        MessageBoxA(h_wnd, p_message, p_caption, MB_OK);

        h.uninstall();
        MessageBoxA(h_wnd, p_message, p_caption, MB_OK);

        println!("{:#?}", h);
    }
}
