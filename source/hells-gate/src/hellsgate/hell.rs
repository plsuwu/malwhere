use core::{arch::asm, ffi::c_void};

static mut SYSTEM_CALL: u32 = 0;

// the `Hell::nt_***` functions below can be condensed into macros so they can be invoked variadically,
// but i do not have even a basic grasp on rust macros and this was mostly just blocking out 
// proof-of-concept functionality

#[no_mangle]
unsafe extern "system" fn descend() {
    return asm!(
            // 'pre-syscall' routine to load SSN
            "mov r10, rcx",
            "mov eax, {0:e}",
            "syscall",          // kernel hand-off

            in(reg) SYSTEM_CALL,

            // we don't want the compiler pushing values to the stack arbitrarily or the arguments we 
            // set up previously won't be correct, we're essentially telling the compiler here that we're
            // not using the stack so it doesn't need to save register values onto the stack 
            // (or something like that)
            options(nostack),
    );
}

#[repr(C)]
pub struct Hell;

// my assembly is pretty rough and as such the asm below could probably be improved
// significantly...
//
// in any case, i was skill issued so hard but getting rustc to cooperate here was 
// actually so evil

impl Hell {
    pub unsafe fn open(syscall: u32) {
        SYSTEM_CALL = 0;
        SYSTEM_CALL = syscall;
    }

    // the extern `fastcall` type seems unnecessary here but the convention is
    // technically `x64 fastcall` so it is what it is at this point
    pub unsafe extern "system" fn nt_allocate_virtual_memory(
        process_handle: *mut c_void,
        base_address: *mut *mut c_void,
        zero_bits: u32,
        region_size: *mut u32,
        allocation_type: u32,
        protect: u32,
    ) -> i32 {

        let result: i32;

        asm!(

            // reserve extra space on stack for arguments 5 + 6,
            // push args 5+ onto stack starting at an offset of 0x20
            // in 8-byte aligned chunks:
            "sub rsp, 0x30",
            "mov dword ptr ss:[rsp+0x28], {5:e}",
            "mov dword ptr ss:[rsp+0x20], {4:e}",

            // move first four args into associated registers

            "mov r9, {3:r}",
            "mov r8, {2:r}",
            "mov rdx, {1}",
            "mov rcx, {0}",

            "call {6}",

            // cleanup stack pointer
            "add rsp, 0x30",

            // first 4 params (ltr) placed in registers:
            //      rcx -> arg0
            //      rdx -> arg1
            //      r8  -> arg2
            //      r9  -> arg3
            in(reg) process_handle,         // 0
            in(reg) base_address,           // 1
            in(reg) zero_bits,              // 2
            in(reg) region_size,            // 3

            // additional args pushed to stack; there is a 16 between our args and
            // `rsp` so 5th arg onwards seems to start at [rsp+0x20] with 8-byte alignment
            in(reg) allocation_type,        // 4 - dword ptr ss:[rsp+<offset>])
            in(reg) protect,                // 5 - dword ptr ss:[rsp+<prev rsp offset + 8 bytes]) 

            // this extra function call is potentially unnecessary but i couldn't get
            // it to work otherwise and i don't know why
            sym descend,                    // 6
            out("rax") result,              // return NTSTATUS (unwrapped base i32 field) from syscall
        );

        return result;
    }

    #[no_mangle]
    pub unsafe extern "system" fn nt_protect_virtual_memory(
        process_handle: *mut std::ffi::c_void,
        base_address: *mut *mut std::ffi::c_void,
        region_size: *mut usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32 {

        let result: i32;

        asm!(
            "sub rsp, 0x8",
            "mov qword ptr ss:[rsp+0x20], {4:r}",

            "mov r9, {3:r}",
            "mov r8, {2:r}",
            "mov rdx, {1}",
            "mov rcx, {0}",

            "call {5}",
            "add rsp, 0x8",

            in(reg) process_handle,                 // 0
            in(reg) base_address as *mut *mut u8,   // 1
            in(reg) region_size,                    // 2
            in(reg) new_protect,                    // 3

            in(reg) old_protect,                    // 4
            sym descend,                            // 5

            out("rax") result,
        );

        return result;
    }

    pub unsafe extern "system" fn nt_create_thread_ex(
        thread_handle: *mut std::ffi::c_void,
        desired_access: u32,
        object_attrs: *const i32,
        process_handle: *const std::ffi::c_void,

        // start_routine is of type `LPTHREAD_START_ROUTINE`, but 
        // its easier to just use the raw ptr type rather than the wrapper type
        start_routine: extern "system" fn(*mut std::ffi::c_void) -> u32,
        argument: *const std::ffi::c_void,

        // create_flags is of type `THREAD_CREATION_FLAGS`, but
        // like above `0 == THREAD_CREATE_RUN_IMMEDIATELY` seems easier here
        create_flags: u32,
        zero_bits: usize,
        stack_size: usize,
        max_stack_size: usize, 
        attribute_list: *const std::ffi::c_void,
    ) -> i32 {

        let mut result: i32;

        // most args we pass here are optional so we're passing a lot of null pointers and 0s;
        // in a more complete implementation it would be better to provide slightly better types 
        // for the parameters but i'd prefer to entirely rework this with macros anyway
        asm!(
             
            "sub rsp, 0x50",  

            "mov qword ptr ss:[rsp+0x20], {4}",
            "mov qword ptr ss:[rsp+0x28], {5}",
            "mov qword ptr ss:[rsp+0x30], {6:r}",
            "mov qword ptr ss:[rsp+0x38], {7}",
            "mov qword ptr ss:[rsp+0x40], {8}",
            "mov qword ptr ss:[rsp+0x48], {9}",
            "mov qword ptr ss:[rsp+0x50], {10}",

            "mov r9, {3}",
            "mov r8, {2}",
            "mov rdx, {1:r}",
            "mov rcx, {0}",

            "call {11}",
            "add rsp, 0x50",

            in(reg) thread_handle,      // 0
            in(reg) desired_access,     // 1
            in(reg) object_attrs,       // 2
            in(reg) process_handle,     // 3

            in(reg) start_routine,      // 4

            in(reg) argument,           // 5
            in(reg) create_flags,       // 6
            in(reg) zero_bits,          // 7
            in(reg) stack_size,         // 8
            in(reg) max_stack_size,     // 9
            in(reg) attribute_list,     // 10

            sym descend,                // 11
            out("rax") result,
        );

        return result;
    }

    // our last two functions don't need to pass args on the stack, so we can 
    // just use registers and forget about the stack :))
    pub unsafe extern "system" fn nt_wait_for_single_object(
        handle: *const std::ffi::c_void,
        alertable: i32,
        timeout: *const i64,
    ) -> i32 {
        let result;

        asm!(
            "mov r8, {2}",
            "mov rdx, {1:r}",
            "mov rcx, {0}",

            "call {3}",
            in(reg) handle,         // 0
            in(reg) alertable,      // 1
            in(reg) timeout,        // 2

            sym descend,            // 3
            out("rax") result,
            options(nostack),
        );

        return result;
    }

    pub unsafe extern "system" fn nt_close(
        handle: *const *const std::ffi::c_void
    ) -> i32 {
        let result: i32;

        asm!(
            "mov rcx, {0}",
            "call {1}",
            in(reg) handle,         // 0
            sym descend,            // 1

            out("rax") result,
            options(nostack),
        );

        return result;
    }
}

// urgh...
