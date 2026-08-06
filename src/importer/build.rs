fn main() {
    windows_bindgen::Bindgen::new()
        .output("src/bindings.rs")
        .flat()
        .sys()
        .extern_fns()
        .filters([
            "PEB",
            "LDR_DATA_TABLE_ENTRY",
            "FARPROC",
            "HMODULE"
        ])
        .write();
}
