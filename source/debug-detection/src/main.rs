use core::{
    cell::Cell,
    ffi::{c_ulong, c_void},
    fmt::Debug,
    i64::MAX,
    panic::AssertUnwindSafe,
    ptr::{null, null_mut},
};
use std::arch::asm;
use std::panic;
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{GetLastError, EXCEPTION_BREAKPOINT, FARPROC, HANDLE, NTSTATUS},
        System::{
            Diagnostics::{
                Debug::{
                    AddVectoredExceptionHandler, DebugBreak, GetThreadContext, IsDebuggerPresent,
                    RemoveVectoredExceptionHandler, SetUnhandledExceptionFilter,
                    UnhandledExceptionFilter, CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64,
                    EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH,
                    EXCEPTION_EXECUTE_HANDLER, EXCEPTION_POINTERS, LPTOP_LEVEL_EXCEPTION_FILTER,
                },
                ToolHelp::{
                    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
                    PROCESSENTRY32W, TH32CS_SNAPPROCESS,
                },
            },
            LibraryLoader::{GetModuleHandleA, GetModuleHandleW, GetProcAddress, LoadLibraryA},
            SystemInformation::{GetTickCount, GetTickCount64},
            SystemServices::PEXCEPTION_FILTER,
            Threading::{
                GetCurrentProcess, GetCurrentThread, PEB, PROCESS_INFORMATION,
                PROCESS_INFORMATION_CLASS,
            },
        },
    },
};

#[inline]
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

// basic check using windows API function call
unsafe fn basic() -> bool {
    let debugged = IsDebuggerPresent().as_bool();
    println!(
        "[+] `IsDebuggerPresent': \t\t\t\t\t\t0x{:016X?}",
        debugged as u64
    );
    return debugged;
}

// via PEB field
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

// via undocumented `ProcessEnvironmentBlock->NtGlobalFlag` field
const FLG_HEAP_ENABLE_TAIL_CHECK: u8 = 0x10;
const FLG_HEAP_ENABLE_FREE_CHECK: u8 = 0x20;
const FLG_HEAP_VALIDATE_PARAMETERS: u8 = 0x40;
const DEBUGGER_PRESENT_NTGLOBALFLAG: u8 =
    FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS; // 0x70 when debugger is attached

unsafe fn peb_nt_globalflag(p_peb: *const PEB) -> bool {
    let p_nt_globalflag = p_peb.byte_add(0xBC) as *const u32; // undocumented `PEB->NtGlobalFlag`
    if *p_nt_globalflag == DEBUGGER_PRESENT_NTGLOBALFLAG as u32 {
        return true;
    }

    return false;
}

// using `NtQueryInformationProcess` function (exported from ntdll.dll)

type NtQueryInformationProcess = unsafe extern "system" fn(
    HANDLE,
    PROCESS_INFORMATION_CLASS,
    *mut u64,
    usize,
    *mut u64,
) -> NTSTATUS;
unsafe fn ntqip_debug() -> bool {
    let mut status: NTSTATUS = NTSTATUS(0x0);
    let mut dw_isdebuggerpresent = 0u64;
    let mut h_processdebugobject = 0u64;
    let p_fn_ntqueryinformationprocess: NtQueryInformationProcess;

    let h_module = GetModuleHandleA(PCSTR::from_raw("NTDLL.DLL\0".as_ptr())).unwrap();
    let p_func = GetProcAddress(
        h_module,
        PCSTR::from_raw("NtQueryInformationProcess\0".as_ptr()),
    )
    .unwrap();

    p_fn_ntqueryinformationprocess = std::mem::transmute(p_func);
    status = p_fn_ntqueryinformationprocess(
        GetCurrentProcess(),
        PROCESS_INFORMATION_CLASS(0x7),
        &mut dw_isdebuggerpresent,
        std::mem::size_of::<u64>(),
        null_mut(),
    );

    println!(
        "[+] `NtQueryInformationProcess<ProcessDebugPort | 0x7>': \t\t0x{:016X?}",
        dw_isdebuggerpresent
    );

    status = p_fn_ntqueryinformationprocess(
        GetCurrentProcess(),
        PROCESS_INFORMATION_CLASS(0x1e),
        &mut h_processdebugobject,
        std::mem::size_of::<u64>(),
        null_mut(),
    );

    println!(
        "[+] `NtQueryInformationProcess<ProcessDebugObjectHandle | 0x1e>': \t0x{:016X?}",
        h_processdebugobject
    );

    return false;
}

unsafe fn hw_breakpoints_set() -> bool {
    let mut ctx: CONTEXT = Default::default();
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;

    let result = GetThreadContext(GetCurrentThread(), &mut ctx).unwrap();
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

const BLIST: [&'static str; 7] = [
    "x64dbg.exe",
    "ida.exe",
    "ida64.exe",
    "VsDebugConsole.exe",
    "msvsmon.exe",
    "qemu-ga.exe",
    "codelldb.exe",
];

unsafe fn running_blacklisted_process() {
    let mut h_snapshot: HANDLE = HANDLE::default();
    let mut proc_entry: PROCESSENTRY32 = PROCESSENTRY32::default();
    let mut b_state = false;
    proc_entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

    h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).unwrap();
    Process32First(h_snapshot, &mut proc_entry);
    loop {
        let ascii_procname = proc_entry
            .szExeFile
            .iter()
            .take_while(|b| **b != 0)
            .map(|b| (*b as u8 as char).to_string())
            .collect::<Vec<_>>()
            .concat();
        // println!("{:?}", ascii_procname);

        for procname in BLIST.iter() {
            if procname == &ascii_procname {
                println!(
                    "[+] Found proc \t\t\t\t\t\t   (PID: {}): {:?}",
                    proc_entry.th32ProcessID, ascii_procname
                );
            }
        }

        if Process32Next(h_snapshot, &mut proc_entry).is_err() {
            break;
        }
    }
}

unsafe fn was_paused_gettickcount() -> bool {
    let mut time_a = 0;
    let mut time_b = 0;

    time_a = GetTickCount64();
    let i = 4_294_967_295u32;

    let mut j = 0;
    while j < i - 2 {
        j += 2;
    }

    time_b = GetTickCount64();
    let rt = time_b - time_a;

    if rt > 2000 {
        println!("[+] Execution seems to have paused here.");
        return true;
    }

    return false;
}

// idk how else to pass this between the handler and our break checker
thread_local! {
    static HANDLED_EXCEPTION: Cell<bool> = Cell::new(true);
}

unsafe extern "system" fn vectored_handler(lp_exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    let record = (*lp_exception_info).ExceptionRecord;
    println!(
        "[*] ExceptionRecord: {:X?} (dbg: {:X?})",
        (*record).ExceptionCode,
        EXCEPTION_BREAKPOINT.0
    );

    if (*record).ExceptionCode == EXCEPTION_BREAKPOINT {
        HANDLED_EXCEPTION.with(|h| h.set(false)); // exception handled programmatically

        // note that we're required to increment instruction pointer for the thread's context
        // otherwise we call this handler function again when the thread resumes (ie, we loop infinitely)
        (*(*lp_exception_info).ContextRecord).Rip += 1;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // different error
    return EXCEPTION_CONTINUE_SEARCH;
}

unsafe fn break_check() -> bool {
    // assign a priority handler in the context of our current thread
    let handler = AddVectoredExceptionHandler(1, Some(vectored_handler));

    // track the exception to see where it gets handled;
    // if the exception is handled by a debugger, this will remain true
    HANDLED_EXCEPTION.with(|h| h.set(true));
    DebugBreak();
    RemoveVectoredExceptionHandler(handler);
    let handled = HANDLED_EXCEPTION.with(|h| h.get());

    println!("[+] DebugBreak handled externally: {:?}", handled);
    return handled;
}

fn main() {
    unsafe {
        let _basic = basic();

        // retrieve PEB base addr
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
