//! testing/debugging runner binary

use common::hashing::crc::Crc32b;
use common::hashing::traits::StringHasher;

use syscall::initialization::SyscallRegistry;

fn main() -> anyhow::Result<()> {
    let syscalls_plaintext = vec![
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
        "NtWaitForSingleObject",
    ];

    let crc_hasher = StringHasher::new(Crc32b);
    let mut hashed = crc_hasher.hash(syscalls_plaintext);

    let table = SyscallRegistry::new(&mut hashed);

    println!("{:#016x?}", table);

    Ok(())
}