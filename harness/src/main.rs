//! testing/debugging runner binary

use common::hashing::crc::Crc32b;
use common::hashing::traits::StringHasher;
use syscall::resolver::SyscallMap;

fn main() -> anyhow::Result<()> {

    let syscalls_plaintext = vec![
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
        "NtWaitForSingleObject",
    ];

    let crc_hasher = StringHasher::new(Crc32b);
    let mut hashed = crc_hasher.hash(syscalls_plaintext);

    let mut table = SyscallMap::new(&mut hashed, Crc32b);
    _ = table.resolve()?;

    println!("{:#016x?}", table);

    Ok(())
}
