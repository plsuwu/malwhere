use bitflags::bitflags;
use common::winapi::CONTEXT;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DRX {
    Dr0,
    Dr1,
    Dr2,
    Dr3,
}

impl DRX {
    pub fn set(&self, ctx: &mut CONTEXT, val: u64) {
        match self {
            DRX::Dr0 => ctx.Dr0 = val,
            DRX::Dr1 => ctx.Dr1 = val,
            DRX::Dr2 => ctx.Dr2 = val,
            DRX::Dr3 => ctx.Dr3 = val,
        }
    }

    pub fn clear(&self, ctx: &mut CONTEXT) {
        match self {
            DRX::Dr0 => ctx.Dr0 = 0x00,
            DRX::Dr1 => ctx.Dr1 = 0x00,
            DRX::Dr2 => ctx.Dr2 = 0x00,
            DRX::Dr3 => ctx.Dr3 = 0x00,
        }
    }
}

bitflags! {
    /// # Usage
    ///
    /// ```ignore
    /// let mut ctl = DRCtl::empty();
    /// ctl.insert(DRCtl::L0 | DRCtl::G0); // flag-style access
    /// ctl.set_field(8, 2, 0b11);         // field-style access at bits 16..=17
    /// ```
    ///
    /// Note that global debug registers are normalized out in user mode, despite what a lot of
    /// information might claim; G0/1/2 can only be set in kernel mode
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct DRCtl: u64 {
        const L0 = 1 << 0;
        const G0 = 1 << 1;
        const L1 = 1 << 2;
        const G1 = 1 << 3;
        const L2 = 1 << 4;
        const G2 = 1 << 5;
        const L3 = 1 << 6;
        const G3 = 1 << 7;

        // avoid truncating unnamed bits
        const _ = !0;
    }
}

impl DRCtl {
    pub fn set_field(&mut self, target_register: u32, count: u32, value: u64) -> u64 {
        let shift = target_register * 2;
        assert!(shift < 64, "field offset out of range");

        // avoid overflowing when `count == 64`
        let mask = 1u64.checked_shl(count).map_or(u64::MAX, |v| v - 1) << shift;

        *self = Self::from_bits_retain((self.bits() & !mask) | ((value << shift) & mask));
        self.bits()
    }
    
    pub fn enable(&mut self, ctx: &mut CONTEXT, reg: DRX) {
        self.insert(reg.into());
        ctx.Dr7 = self.bits();
    }

    pub fn disable(&mut self, ctx: &mut CONTEXT, reg: DRX) {
        self.set(reg.into(), false);
        ctx.Dr7 = self.bits();
    }
}

impl From<DRX> for usize {
    fn from(val: DRX) -> Self {
        match val {
            DRX::Dr0 => 0,
            DRX::Dr1 => 1,
            DRX::Dr2 => 2,
            DRX::Dr3 => 3,
        }
    }
}

impl From<DRX> for DRCtl {
    fn from(val: DRX) -> Self {
        match val {
            DRX::Dr0 => DRCtl::L0,
            DRX::Dr1 => DRCtl::L1,
            DRX::Dr2 => DRCtl::L2,
            DRX::Dr3 => DRCtl::L3,
        }
    }
}
