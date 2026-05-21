use subtle::ConstantTimeEq;

#[derive(Clone, Copy)]
pub struct Key(pub [u8; 32]);

impl ConstantTimeEq for Key {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.as_slice().ct_eq(other.0.as_slice())
    }
}

pub const PRIVATE_KEY_1: Key = Key([
    0xb0, 0x3b, 0x34, 0xc3, 0x3a, 0x1c, 0x44, 0xf2, 0x25, 0xb6, 0x62, 0xd2, 0xbf, 0x48, 0x59, 0xb8,
    0x13, 0x54, 0x11, 0xfa, 0x7b, 0x03, 0x86, 0xd4, 0x5f, 0xb7, 0x5d, 0xc5, 0xb9, 0x1b, 0x44, 0x66,
]);

pub const PRIVATE_KEY_2: Key = Key([
    0xc8, 0x06, 0x43, 0x9d, 0xc9, 0xd2, 0xc4, 0x76, 0xff, 0xed, 0x8f, 0x25, 0x80, 0xc0, 0x88, 0x8d,
    0x58, 0xab, 0x40, 0x6b, 0xf7, 0xae, 0x36, 0x98, 0x87, 0x90, 0x21, 0xb9, 0x6b, 0xb4, 0xbf, 0x59,
]);

/// A `#[repr(C)]` struct with a padding byte between `x` and `y`.
/// Total size = 4 bytes: [x, padding, y_lo, y_hi].
///
/// `ConstantTimeEq` compares fields, not raw bytes, so padding is irrelevant.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Padded {
    pub x: u8,
    pub y: u16,
}

impl ConstantTimeEq for Padded {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.x.ct_eq(&other.x) & self.y.ct_eq(&other.y)
    }
}

/// A `#[repr(C, packed)]` struct with no padding.
/// Total size = 3 bytes: [x, y_lo, y_hi].
///
/// Fields are copied to locals before comparison to avoid unaligned references.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Packed {
    pub x: u8,
    pub y: u16,
}

impl ConstantTimeEq for Packed {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        let (sx, sy) = (self.x, self.y);
        let (ox, oy) = (other.x, other.y);
        sx.ct_eq(&ox) & sy.ct_eq(&oy)
    }
}
