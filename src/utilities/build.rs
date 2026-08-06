fn main() {
    windows_bindgen::Bindgen::new()
        .output("src/bindings.rs")
        .flat()
        .sys()
        .extern_fns()
        .filters([
            "STD_OUTPUT_HANDLE",
            "STD_ERROR_HANDLE",
            "HANDLE",
            "MAX_PATH",

            "GetStdHandle",
            "WriteFile",
            "ExitProcess",
            "GetLastError",
        ])
        .write();
}