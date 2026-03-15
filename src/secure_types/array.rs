use core::fmt;
use std::{
    borrow::{Borrow, BorrowMut},
    str::FromStr,
};

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::secure_utils::memlock;

/// A data type suitable for storing sensitive information such as passwords and private keys in memory, that implements:
///
/// - Automatic zeroing in `Drop`
/// - Constant time comparison in `PartialEq` (does not short circuit on the first different character; but terminates instantly if strings have different length)
/// - Outputting `***SECRET***` to prevent leaking secrets into logs in `fmt::Debug` and `fmt::Display`
/// - Automatic `mlock` to protect against leaking into swap (any unix)
/// - Automatic `madvise(MADV_NOCORE/MADV_DONTDUMP)` to protect against leaking into core dumps (FreeBSD, DragonflyBSD, Linux)
#[derive(Eq, PartialOrd, Ord, Hash)]
pub struct SecureArray<const LENGTH: usize>
where
    u8: Copy + Zeroize,
{
    pub(crate) content: [u8; LENGTH],
}

impl<const LENGTH: usize> SecureArray<LENGTH> {
    pub fn new(mut content: [u8; LENGTH]) -> Self {
        memlock::mlock(content.as_mut_ptr(), content.len());
        Self { content }
    }

    /// Borrow the contents of the string.
    pub fn unsecure(&self) -> &[u8] {
        self.borrow()
    }

    /// Mutably borrow the contents of the string.
    pub fn unsecure_mut(&mut self) -> &mut [u8] {
        self.borrow_mut()
    }

    /// Overwrite the string with zeros. This is automatically called in the destructor.
    pub fn zero_out(&mut self) {
        self.content.zeroize()
    }
}

impl<const LENGTH: usize> PartialEq for SecureArray<LENGTH> {
    fn eq(&self, other: &SecureArray<LENGTH>) -> bool {
        self.content.as_slice().ct_eq(other.content.as_slice()).into()
    }
}

impl<const LENGTH: usize> Clone for SecureArray<LENGTH> {
    fn clone(&self) -> Self {
        Self::new(self.content)
    }
}

// Creation
impl<const LENGTH: usize> From<[u8; LENGTH]> for SecureArray<LENGTH>
where
    u8: Copy + Zeroize,
{
    fn from(s: [u8; LENGTH]) -> Self {
        Self::new(s)
    }
}

impl<const LENGTH: usize> TryFrom<Vec<u8>> for SecureArray<LENGTH>
where
    u8: Copy + Zeroize,
{
    type Error = String;

    fn try_from(s: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self::new(s.try_into().map_err(|error: Vec<u8>| {
            format!("length mismatch: expected {LENGTH}, but got {}", error.len())
        })?))
    }
}

impl<const LENGTH: usize> FromStr for SecureArray<LENGTH> {
    type Err = std::array::TryFromSliceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(SecureArray::new(s.as_bytes().try_into()?))
    }
}

// Array item indexing
impl<U, const LENGTH: usize> std::ops::Index<U> for SecureArray<LENGTH>
where
    [u8; LENGTH]: std::ops::Index<U>,
{
    type Output = <[u8; LENGTH] as std::ops::Index<U>>::Output;

    fn index(&self, index: U) -> &Self::Output {
        std::ops::Index::index(&self.content, index)
    }
}

// Borrowing
impl<const LENGTH: usize> Borrow<[u8]> for SecureArray<LENGTH> {
    fn borrow(&self) -> &[u8] {
        self.content.borrow()
    }
}

impl<const LENGTH: usize> BorrowMut<[u8]> for SecureArray<LENGTH> {
    fn borrow_mut(&mut self) -> &mut [u8] {
        self.content.borrow_mut()
    }
}

// Overwrite memory with zeros when we're done
impl<const LENGTH: usize> Drop for SecureArray<LENGTH> {
    fn drop(&mut self) {
        self.zero_out();
        memlock::munlock(self.content.as_mut_ptr(), self.content.len());
    }
}

// Make sure sensitive information is not logged accidentally
impl<const LENGTH: usize> fmt::Debug for SecureArray<LENGTH> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| fmt::Error)
    }
}

impl<const LENGTH: usize> fmt::Display for SecureArray<LENGTH> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| fmt::Error)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::SecureArray;

    #[test]
    fn test_basic() {
        let my_sec: SecureArray<5> = SecureArray::from_str("hello").unwrap();
        assert_eq!(my_sec, SecureArray::from_str("hello").unwrap());
        assert_eq!(my_sec.unsecure(), b"hello");
    }

    #[test]
    fn test_zero_out() {
        let mut my_sec: SecureArray<5> = SecureArray::from_str("hello").unwrap();
        my_sec.zero_out();
        assert_eq!(my_sec.unsecure(), b"\x00\x00\x00\x00\x00");
    }

    #[test]
    fn test_comparison() {
        assert_eq!(SecureArray::<5>::from_str("hello").unwrap(), SecureArray::from_str("hello").unwrap());
        assert_ne!(SecureArray::<5>::from_str("hello").unwrap(), SecureArray::from_str("olleh").unwrap());
    }

    #[test]
    fn test_indexing() {
        let string: SecureArray<5> = SecureArray::from_str("hello").unwrap();
        assert_eq!(string[0], b'h');
        assert_eq!(&string[3..5], "lo".as_bytes());
    }

    #[test]
    fn test_show() {
        assert_eq!(format!("{:?}", SecureArray::<5>::from_str("hello").unwrap()), "***SECRET***".to_string());
        assert_eq!(format!("{}", SecureArray::<5>::from_str("hello").unwrap()), "***SECRET***".to_string());
    }

    // TODO
    // #[test]
    // fn test_comparison_zero_out_mb() {
    //     let mbstring1 = SecureArray::<8>::from(['H', 'a', 'l', 'l', 'o', ' ', '🦄', '!']);
    //     let mbstring2 = SecureArray::<8>::from(['H', 'a', 'l', 'l', 'o', ' ', '🦄', '!']);
    //     let mbstring3 = SecureArray::<8>::from(['!', '🦄', ' ', 'o', 'l', 'l', 'a', 'H']);
    //     assert!(mbstring1 == mbstring2);
    //     assert!(mbstring1 != mbstring3);
    //
    //     let mut mbstring = mbstring1.clone();
    //     mbstring.zero_out();
    //     for (given, expected) in zip(mbstring.unsecure(), ['\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0']) {
    //         assert_eq!(*given, expected as u8);
    //     }
    // }
}
