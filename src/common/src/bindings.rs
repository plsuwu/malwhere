pub type PSLIST_HEADER = *mut SLIST_HEADER;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SINGLE_LIST_ENTRY {
    pub Next: *mut Self,
}
#[cfg(target_arch = "x86")]
pub type SLIST_ENTRY = SINGLE_LIST_ENTRY;
#[repr(C)]
#[cfg(target_arch = "x86")]
#[derive(Clone, Copy)]
pub union SLIST_HEADER {
    pub Alignment: ULONGLONG,
    pub Anonymous: SLIST_HEADER_0,
}
#[cfg(target_arch = "x86")]
impl Default for SLIST_HEADER {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[cfg(target_arch = "x86")]
#[derive(Clone, Copy, Default)]
pub struct SLIST_HEADER_0 {
    pub Next: SLIST_ENTRY,
    pub Depth: WORD,
    pub CpuId: WORD,
}
#[repr(C, align(16))]
#[cfg(any(target_arch = "arm64ec", target_arch = "x86_64"))]
#[derive(Clone, Copy)]
pub union SLIST_HEADER {
    pub Anonymous: SLIST_HEADER_0,
    pub HeaderX64: SLIST_HEADER_1,
}
#[cfg(any(target_arch = "arm64ec", target_arch = "x86_64"))]
impl Default for SLIST_HEADER {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[cfg(any(target_arch = "arm64ec", target_arch = "x86_64"))]
#[derive(Clone, Copy, Default)]
pub struct SLIST_HEADER_0 {
    pub Alignment: ULONGLONG,
    pub Region: ULONGLONG,
}
#[repr(C)]
#[cfg(any(target_arch = "arm64ec", target_arch = "x86_64"))]
#[derive(Clone, Copy, Default)]
pub struct SLIST_HEADER_1 {
    pub _bitfield1: u64,
    pub _bitfield2: u64,
}
#[repr(C, align(16))]
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy)]
pub union SLIST_HEADER {
    pub Anonymous: SLIST_HEADER_0,
    pub HeaderArm64: SLIST_HEADER_1,
}
#[cfg(target_arch = "aarch64")]
impl Default for SLIST_HEADER {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy, Default)]
pub struct SLIST_HEADER_0 {
    pub Alignment: ULONGLONG,
    pub Region: ULONGLONG,
}
#[repr(C)]
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy, Default)]
pub struct SLIST_HEADER_1 {
    pub _bitfield1: u64,
    pub _bitfield2: u64,
}
pub type ULONGLONG = u64;
pub type WORD = u16;
