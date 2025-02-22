# malwhere

assorted malware techniques.

> no payloads are malicious

|directory |language |technique |
|---  |--- |--- |
|[hells-gate](https://github.com/plsuwu/malwhere/tree/main/source/hells-gate)  |Rust |Rust implementation of the [hell's gate](https://github.com/am0nsec/HellsGate) dynamic syscall invocation technique. |
|[api-hooking](https://github.com/plsuwu/malwhere/blob/main/source/api-hooking) |Rust |Windows API function hooking with a simple shellcode trampoline. |
|[hardware-breakpoint-hooking](https://github.com/plsuwu/malwhere/tree/main/source/hardware-breakpoint-hooking) |Rust |Patchless function hooking technique (local thread context*) that utilizes hardware breakpoints and vectored exception handlers to redirect thread execution. | 
|[custom-api-functions](https://github.com/plsuwu/malwhere/tree/main/source/custom-api-functions) |Rust |Dynamically resolves (?) Windows API function addresses from the ProcessEnvironmentBlock. | 
|[debug-detection](https://github.com/plsuwu/malwhere/tree/main/source/debug-detection) |Rust |A handful of methods to detect debuggers. |
|[fn-stomping](https://github.com/plsuwu/malwhere/tree/main/source/fn-stomping) |Rust |Re-writes the bytes of a benign API function in the context of a local process. |
|[stager-registry](https://github.com/plsuwu/malwhere/blob/main/source/stager-registry/src/main.rs) |Rust |Writes a payload to the Windows registry and executes it. |
