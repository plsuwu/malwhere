pub type DWORD = u32;
pub type LONGLONG = i64;
#[repr(C)]
#[derive(Clone, Copy)]
pub union LARGE_INTEGER {
    pub Anonymous: LARGE_INTEGER_0,
    pub u: LARGE_INTEGER_1,
    pub QuadPart: LONGLONG,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LARGE_INTEGER_0 {
    pub LowPart: DWORD,
    pub HighPart: LONG,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LARGE_INTEGER_1 {
    pub LowPart: DWORD,
    pub HighPart: LONG,
}
pub type LONG = i32;
