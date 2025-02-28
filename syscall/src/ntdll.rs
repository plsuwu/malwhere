// use common::environment_block::fetcher::Module;
// use lazy_static::lazy_static;
// use std::sync::Mutex;
//
// lazy_static! {
//     static ref CONFIG: Mutex<NtdllConfig> = {
//         let config = NtdllConfig::init().unwrap();
//
//         Mutex::new(config)
//     };
// }
//
// unsafe impl Send for NtdllConfig {}
// unsafe impl Sync for NtdllConfig {}
//
// #[repr(C)]
// #[derive(Debug)]
// pub struct NtdllConfig {
//     pub ntdll: Module,
// }
//
// impl NtdllConfig {
//     pub(crate) fn init() -> anyhow::Result<Self> {
//         let ntdll_base = Module::ntdll_base()?;
//
//         println!("{:#?}", ntdll_base);
//
//         let self_zeroed = unsafe { std::mem::zeroed() };
//         Ok(self_zeroed)
//     }
// }

