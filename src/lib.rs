//! A data type suitable for storing sensitive information such as passwords and
//! private keys in memory, featuring constant time equality, mlock and zeroing
//! out.

mod secure_types;
mod secure_utils;

#[cfg(test)]
mod test_utils;

#[cfg(feature = "serde")]
mod serde;

pub use secure_types::array::SecureArray;
pub use secure_types::boxed::SecureBox;
pub use secure_types::string::SecureString;
pub use secure_types::vec::{SecureBytes, SecureVec};
pub use subtle::ConstantTimeEq;

#[doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;
