#[macro_export]
macro_rules! get_param {
    ($ctx:expr, $num:expr) => {
        unsafe { crate::hook::context::get_function_argument($ctx, $num) }
    };
}

#[macro_export]
macro_rules! set_param {
    ($ctx:expr, $val:expr, $num:expr) => {
        unsafe { crate::hook::context::set_function_argument($ctx, $val, $num) }
    };
}