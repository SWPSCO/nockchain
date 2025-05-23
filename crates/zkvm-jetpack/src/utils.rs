// Utility functions and commonly used re-exports

use nockvm::noun::IndirectAtom;
pub use tracing::{debug, trace};

// tests whether a felt atom has the leading 1. we cannot actually test
// Felt, because it doesn't include the leading 1.
pub fn felt_atom_is_valid(felt_atom: IndirectAtom) -> bool {
    let dat_ptr = felt_atom.data_pointer();
    unsafe { *(dat_ptr.add(3)) == 0x1 }
}