//! testing/debugging runner binary

use common::hashing::djb::Djb;
use common::hashing::traits::StringHasher;

use syscall::initialization::SyscallRegistry;

fn main() -> anyhow::Result<()> {
    let plains = Vec::from(["a", "b", "c"]);
    let djb = StringHasher::new(Djb);
    let mut hashed = djb.hash(plains);

    let table = SyscallRegistry::new(&mut hashed);

    println!("{:#016x?}", table);

    Ok(())
}