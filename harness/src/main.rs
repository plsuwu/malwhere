//! testing/debugging runner module

use common::remote::thread::{Thread};

fn main() -> anyhow::Result<()> {

    let target_proc = String::from("notepad.exe");

    _ = Thread::list_remote_threads(&target_proc)?;
    let remote_thread = Thread::get_threads(&target_proc)?;

    println!("{:#?}", remote_thread);

    Ok(())
}