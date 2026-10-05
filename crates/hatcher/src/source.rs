//! Reversible octet input for the character parser.
use std::cell::Cell;

thread_local! {
    static BYTE_MODE: Cell<bool> = const { Cell::new(false) };
}

struct ByteModeGuard(bool);
impl Drop for ByteModeGuard {
    fn drop(&mut self) {
        BYTE_MODE.with(|mode| mode.set(self.0));
    }
}

/// Map every source octet to the same-valued character, without decoding UTF-8.
pub fn decode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| char::from(*byte)).collect()
}

/// Recover source octets. Characters outside the octet alphabet are errors.
pub fn encode(source: &str) -> Result<Vec<u8>, String> {
    source
        .chars()
        .map(|ch| {
            u8::try_from(ch as u32).map_err(|_| {
                "byte source contains a character outside its octet alphabet".to_owned()
            })
        })
        .collect()
}

/// Run parser operations on an already mapped octet string.
pub fn with_byte_mode<T>(parse: impl FnOnce() -> T) -> T {
    let previous = BYTE_MODE.with(|mode| mode.replace(true));
    let _guard = ByteModeGuard(previous);
    parse()
}

/// Parse raw source bytes without replacing or re-encoding any source octet.
pub fn with_bytes<T>(bytes: &[u8], parse: impl FnOnce(&str) -> T) -> T {
    let source = decode(bytes);
    with_byte_mode(|| parse(&source))
}

/// Translate a mapped UTF-8 boundary into its original source byte offset.
pub fn original_offset(source: &str, offset: usize) -> usize {
    source[..offset].chars().count()
}

/// Whether this thread is parsing a mapped octet string.
pub fn byte_mode() -> bool {
    BYTE_MODE.with(Cell::get)
}

pub(crate) fn character_bytes(ch: char) -> Vec<u8> {
    if byte_mode() {
        vec![u8::try_from(ch as u32).expect("mapped source character is an octet")]
    } else {
        let mut bytes = [0; 4];
        ch.encode_utf8(&mut bytes).as_bytes().to_vec()
    }
}

pub(crate) fn source_bytes(source: &str) -> Vec<u8> {
    if byte_mode() {
        encode(source).expect("mapped source characters are octets")
    } else {
        source.as_bytes().to_vec()
    }
}
