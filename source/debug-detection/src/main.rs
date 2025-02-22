use core::{cell::Cell, ptr::null_mut};
use std::arch::asm;
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{GetLastError, EXCEPTION_BREAKPOINT, HANDLE, NTSTATUS},
        System::{
            Diagnostics::{
                Debug::{
                    AddVectoredExceptionHandler, DebugBreak, GetThreadContext, IsDebuggerPresent,
                    RemoveVectoredExceptionHandler, CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64,
                    EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
                },
                ToolHelp::{
                    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
                    TH32CS_SNAPPROCESS,
                },
            },
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
            SystemInformation::GetTickCount64,
            Threading::{GetCurrentProcess, GetCurrentThread, PEB, PROCESS_INFORMATION_CLASS},
        },
    },
};

// blacklist used in process enum check function
const BLIST: [&'static str; 7] = [
    "x64dbg.exe",
    "ida.exe",
    "ida64.exe",
    "VsDebugConsole.exe",
    "msvsmon.exe",
    "qemu-ga.exe",
    "codelldb.exe",
];

// exception handler setup for the breakpoint exception check
thread_local! {
    static HANDLED_EXCEPTION: Cell<bool> = Cell::new(true);
}

/// Read an offset from the GS register
#[cfg(target_arch = "x86_64")]
unsafe fn __readgsqword(offset: u64) -> u64 {
    let res: u64;
    asm!(
        "mov {}, qword ptr gs:[{}]",
        out(reg) res,
        in(reg) offset,
        options(nostack, preserves_flags)
    );

    return res;
}

/// Detect debuggers using a standalone API call
unsafe fn basic() -> bool {
    let debugged = IsDebuggerPresent().as_bool();
    println!(
        "[+] `IsDebuggerPresent': \t\t\t\t\t\t0x{:016X?}",
        debugged as u64
    );
    return debugged;
}

/// Detect debuggers via the (documented) `BeingDebugged` field of the `PEB`.
unsafe fn peb_beingdebugged(p_peb: *const PEB) -> bool {
    println!(
        "[+] `ProcessEnvironmentBlock->BeingDebugged': \t\t\t\t0x{:016X?}",
        (*p_peb).BeingDebugged
    );

    if (*p_peb).BeingDebugged == 1 {
        return true;
    }

    return false;
}

// `DEBUGGER_PRESENT_NTGLOBALFLAG == 0x70` when debugger is attached due to  combination of the 
// below flags
const FLG_HEAP_ENABLE_TAIL_CHECK: u8 = 0x10;
const FLG_HEAP_ENABLE_FREE_CHECK: u8 = 0x20;
const FLG_HEAP_VALIDATE_PARAMETERS: u8 = 0x40;
const DEBUGGER_PRESENT_NTGLOBALFLAG: u8 =
    FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS;   

/// Detect debuggers via the (undocumented) `NtGlobalFlag` field of the `PEB`.
unsafe fn peb_nt_globalflag(p_peb: *const PEB) -> bool {
    let p_nt_globalflag = p_peb.byte_add(0xBC) as *const u32;       // undocumented `PEB->NtGlobalFlag`
    if *p_nt_globalflag == DEBUGGER_PRESENT_NTGLOBALFLAG as u32 {
        return true;
    }

    return false;
}


type NtQueryInformationProcess = unsafe extern "system" fn(
    HANDLE,
    PROCESS_INFORMATION_CLASS,
    *mut u64,
    usize,
    *mut u64,
) -> NTSTATUS;

/// Detect debuggers via the (undocumented) `NtQueryInformationProcess` function (exported by `NTDLL`).
unsafe fn ntqip_debug() -> bool {
    let mut status: NTSTATUS;
    let mut dw_isdebuggerpresent = 0u64;
    let mut h_processdebugobject = 0u64;
    let p_fn_ntqueryinformationprocess: NtQueryInformationProcess;

    // retrieve handle to `ntdll.dll` module and its `NtQueryInformationProcess` function
    let h_module = GetModuleHandleA(PCSTR::from_raw("NTDLL.DLL\0".as_ptr())).unwrap();
    let p_func = GetProcAddress(
        h_module,
        PCSTR::from_raw("NtQueryInformationProcess\0".as_ptr()),
    )
    .unwrap();

    // call function via its base address (transmuted into a function pointer type)
    p_fn_ntqueryinformationprocess = std::mem::transmute(p_func);
    status = p_fn_ntqueryinformationprocess(
        GetCurrentProcess(),
        PROCESS_INFORMATION_CLASS(0x7),     // 0x7 -> `ProcessDebugPort` flag
        &mut dw_isdebuggerpresent,          // debugger present if this returns non-zero
        std::mem::size_of::<u64>(),
        null_mut(),
    );
    if status.0 != 0x0 {
        println!("[x] NtQueryInformationProcess with `0x7` | `ProcessDebugPort` failed.");
        println!("[x] status: {:#016x?} | last error: {:#016x?}", status, GetLastError());
    }

    println!(
        "[+] `NtQueryInformationProcess<ProcessDebugPort | 0x7>': \t\t0x{:016X?}",
        dw_isdebuggerpresent
    );

    status = p_fn_ntqueryinformationprocess(
        GetCurrentProcess(),
        PROCESS_INFORMATION_CLASS(0x1e),    // 0x1e -> `ProcessDebugObjectHandle` flag (undocumented)
        &mut h_processdebugobject,          // debugger present if this returns non-zero (?)
        std::mem::size_of::<u64>(),
        null_mut(),
    );
    if status.0 != 0x0 {
        println!("[x] NtQueryInformationProcess with `0x1e` | `ProcessDebugObjectHandle` failed.");
        println!("[x] status: {:#016x?} | last error: {:#016x?}", status, GetLastError());
    }

    println!(
        "[+] `NtQueryInformationProcess<ProcessDebugObjectHandle | 0x1e>': \t0x{:016X?}",
        h_processdebugobject
    );

    return false;
}

/// Detect debuggers if hardware breakpoints are set through the current thread's 
/// `CONTEXT` struct (`CONTEXT.Dr{1, 2, 3, 4}`)
unsafe fn hw_breakpoints_set() -> bool {
    let mut ctx: CONTEXT = Default::default();
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;

    if GetThreadContext(GetCurrentThread(), &mut ctx).is_err() {
        println!("
            [x] GetThreadContext failed: last error - {:#016x?}", 
            GetLastError()
        );
    }

    let dbg_regs = vec![ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3];

    println!("[+] Memory addresses in hardware debug registers:");
    for (i, reg) in dbg_regs.iter().enumerate() {
        println!("\t\t\t\t\t\t\t    ---->  Dr{}: 0x{:016X?}", i, reg);
    }

    if dbg_regs.iter().any(|&reg| reg > 0) {
        return true;
    }

    return false;
}

/// Check running processes against a list of analysis programs and debuggers; obviously the above
/// is non-exhaustive and can be added to as required.
unsafe fn running_blacklisted_process() {
    let h_snapshot: HANDLE;
    let mut proc_entry: PROCESSENTRY32 = PROCESSENTRY32::default();
    proc_entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

    // create a snapshot of running processes and retrieve details on the first 
    // process in the snapshot
    h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).unwrap();
    if Process32First(h_snapshot, &mut proc_entry).is_err() {
        return;
    }

    // check the names of processes captured in the snapshot
    loop {
        let ascii_procname = proc_entry
            .szExeFile
            .iter()
            .take_while(|b| **b != 0)
            .map(|b| (*b as u8 as char).to_string())
            .collect::<Vec<_>>()
            .concat();

        for procname in BLIST.iter() {

            // we just print the name to `stdout` if it matches a name in the blacklist, but
            // you'd ideally do something here like self-deletion or API hammering or random
            // calculations or something
            if procname == &ascii_procname {
                println!(
                    "[+] Found proc \t\t\t\t\t\t   (PID: {}): {:?}",
                    proc_entry.th32ProcessID, ascii_procname
                );
            }
        }

        // if it didn't match, cycle to the next process in the snapshot; if no
        // processes left in snapshot, break out of loop.
        if Process32Next(h_snapshot, &mut proc_entry).is_err() {
            break;
        }
    }
}


/// Detect execution breaks via `GetTickCount64` - this can also be done with the higher-resolution 
/// `QueryPerformanceCounter` timer, but its essentially the same routine so I won't bother too much.
unsafe fn was_paused_gettickcount() -> bool {
    let time_a;
    let time_b;

    time_a = GetTickCount64();

    // random garbage computations, this could be more effective if replaced with a debugger
    // check (or another function if you want im not god) to verify that a breakpoint wasn't
    // set to e.g modify register values to circumvent a debugger check or something
    let i = 4_294_967_295u32;
    let mut j = 0;
    while j < i - 2 {
        j += 2;
    }

    time_b = GetTickCount64();
    let rt = time_b - time_a;

    // precomputed tick count on an i7-12700k, i assume this vary
    // depending on the processor of the target machine
    if rt > 2000 {      
        println!("[+] Execution seems to have paused here.");
        return true;
    }

    return false;
}

/// Exception handler for the `break_check()` function below
unsafe extern "system" fn vectored_handler(lp_exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    let record = (*lp_exception_info).ExceptionRecord;
    println!(
        "[*] ExceptionRecord: {:X?} (dbg: {:X?})",
        (*record).ExceptionCode,
        EXCEPTION_BREAKPOINT.0
    );

    if (*record).ExceptionCode == EXCEPTION_BREAKPOINT {
        HANDLED_EXCEPTION.with(|h| h.set(false)); // exception handled internally

        // note that we're required to increment the instruction pointer for this thread's context
        // otherwise we call this handler function again when the thread resumes (ie, we loop infinitely)
        (*(*lp_exception_info).ContextRecord).Rip += 1;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // different error that we don't care about
    return EXCEPTION_CONTINUE_SEARCH;
}

/// Detect prescense of debuggers by checking how the `DebugBreak()` exception is handled
unsafe fn break_check() -> bool {
    // assign a priority handler in the context of our current thread
    let handler = AddVectoredExceptionHandler(1, Some(vectored_handler));

    // track the exception to see where it gets handled;
    // if the exception is handled by a debugger, this will remain true
    HANDLED_EXCEPTION.with(|h| h.set(true));
    DebugBreak();
    RemoveVectoredExceptionHandler(handler);
    let handled = HANDLED_EXCEPTION.with(|h| h.get());

    println!("[+] DebugBreak handled externally?: {:?}", handled);
    return handled;
}

fn main() {
    unsafe {
        let _basic = basic();

        // retrieve PEB base addr for the checks requiring PEB struct data
        let p_peb: *const PEB = __readgsqword(0x60) as *const PEB;
        let _peb_beingdebugged = peb_beingdebugged(p_peb);
        let _peb_ntglobalflag = peb_nt_globalflag(p_peb);

        let _nt_queryinformationprocess = ntqip_debug();
        let _hw_breakpoints = hw_breakpoints_set();
        let _blacklisted = running_blacklisted_process();
        let _pe_gtc = was_paused_gettickcount();

        let _break_check = break_check();
    }
}
