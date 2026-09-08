# Malwhere


## Linux

things 2 explore:

[ ] Process injection
- allegedly this is slightly less "direct" (vs. Windows' `VirtualAllocEx`) due to how Linux works re. remote memory allocation

[ ] `LD_PRELOAD` hooking: e.g. [poliva/ldpreloadhook](https://github.com/poliva/ldpreloadhook)

[ ] Loadable kernel modules
- i.e. dynamically loading malicious modules into the kernel

[ ] Intercepting system calls (e.g. [`sys_getdents`](https://www.man7.org/linux/man-pages/man2/getdents.2.html) to hide files for evasion)
