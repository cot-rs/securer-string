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
///
/// Be careful with `SecureVec::from`: if you have a borrowed string, it will be copied.
/// Use `SecureVec::new` if you have a `Vec<u8>`.
#[derive(Eq, PartialOrd, Ord, Hash)]
pub struct SecureVec {
    pub(crate) content: Vec<u8>,
}

/// Type alias for a vector that stores just bytes
pub type SecureBytes = SecureVec;

impl SecureVec {
    pub fn new(mut cont: Vec<u8>) -> Self {
        memlock::mlock(cont.as_mut_ptr(), cont.capacity());
        SecureVec { content: cont }
    }

    /// Borrow the contents of the string.
    pub fn unsecure(&self) -> &[u8] {
        self.borrow()
    }

    /// Mutably borrow the contents of the string.
    pub fn unsecure_mut(&mut self) -> &mut [u8] {
        self.borrow_mut()
    }

    /// Resizes the `SecureVec` in-place so that len is equal to `new_len`.
    ///
    /// If `new_len` is smaller the inner vector is truncated.
    /// If `new_len` is larger the inner vector will grow, placing `value` in all new cells.
    ///
    /// This ensures that the new memory region is secured if reallocation occurs.
    ///
    /// Similar to [`Vec::resize`](https://doc.rust-lang.org/std/vec/struct.Vec.html#method.resize)
    pub fn resize(&mut self, new_len: usize, value: u8) {
        // Truncate if shorter or same length
        if new_len <= self.content.len() {
            self.content.truncate(new_len);
            return;
        }

        // Allocate new vector, copy old data into it
        let mut new_vec = vec![value; new_len];
        memlock::mlock(new_vec.as_mut_ptr(), new_vec.capacity());
        new_vec[0..self.content.len()].copy_from_slice(&self.content);

        // Securely clear old vector, replace with new vector
        self.zero_out();
        memlock::munlock(self.content.as_mut_ptr(), self.content.capacity());
        self.content = new_vec;
    }

    /// Overwrite the string with zeros. This is automatically called in the destructor.
    ///
    /// This also sets the length to `0`.
    pub fn zero_out(&mut self) {
        self.content.zeroize()
    }
}

impl PartialEq for SecureVec {
    fn eq(&self, other: &SecureVec) -> bool {
        self.content.as_slice().ct_eq(other.content.as_slice()).into()
    }
}

impl Clone for SecureVec {
    fn clone(&self) -> Self {
        Self::new(self.content.clone())
    }
}

// Creation
impl<U> From<U> for SecureVec
where
    U: Into<Vec<u8>>,
{
    fn from(s: U) -> SecureVec {
        SecureVec::new(s.into())
    }
}

impl FromStr for SecureVec {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(SecureVec::new(s.into()))
    }
}

// Vec item indexing
impl<U> std::ops::Index<U> for SecureVec
where
    Vec<u8>: std::ops::Index<U>,
{
    type Output = <Vec<u8> as std::ops::Index<U>>::Output;

    fn index(&self, index: U) -> &Self::Output {
        std::ops::Index::index(&self.content, index)
    }
}

// Borrowing
impl Borrow<[u8]> for SecureVec {
    fn borrow(&self) -> &[u8] {
        self.content.borrow()
    }
}

impl BorrowMut<[u8]> for SecureVec {
    fn borrow_mut(&mut self) -> &mut [u8] {
        self.content.borrow_mut()
    }
}

// Overwrite memory with zeros when we're done
impl Drop for SecureVec {
    fn drop(&mut self) {
        self.zero_out();
        memlock::munlock(self.content.as_mut_ptr(), self.content.capacity());
    }
}

// Make sure sensitive information is not logged accidentally
impl fmt::Debug for SecureVec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| fmt::Error)
    }
}

impl fmt::Display for SecureVec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| fmt::Error)
    }
}

#[cfg(test)]
mod tests {
    use super::{SecureBytes, SecureVec};

    #[test]
    fn test_basic() {
        let my_sec = SecureBytes::from("hello");
        assert_eq!(my_sec, SecureBytes::from("hello".to_string()));
        assert_eq!(my_sec.unsecure(), b"hello");
    }

    #[test]
    fn test_zero_out() {
        let mut my_sec = SecureBytes::from("hello");
        my_sec.zero_out();
        // `zero_out` sets the `len` to 0, here we reset it to check that the bytes were zeroed
        unsafe { my_sec.content.set_len(5) }
        assert_eq!(my_sec.unsecure(), b"\x00\x00\x00\x00\x00");
    }

    #[test]
    fn test_resize() {
        let mut my_sec = SecureVec::from([0u8, 1u8]);
        assert_eq!(my_sec.unsecure().len(), 2);
        my_sec.resize(1, 0);
        assert_eq!(my_sec.unsecure().len(), 1);
        my_sec.resize(16, 2);
        assert_eq!(my_sec.unsecure(), &[0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]);
    }

    #[test]
    fn test_comparison() {
        assert_eq!(SecureBytes::from("hello"), SecureBytes::from("hello"));
        assert!(SecureBytes::from("hello") != SecureBytes::from("yolo"));
        assert!(SecureBytes::from("hello") != SecureBytes::from("olleh"));
        assert!(SecureBytes::from("hello") != SecureBytes::from("helloworld"));
        assert!(SecureBytes::from("hello") != SecureBytes::from(""));
    }

    #[test]
    fn test_indexing() {
        let string = SecureBytes::from("hello");
        assert_eq!(string[0], b'h');
        assert_eq!(&string[3..5], "lo".as_bytes());
    }

    #[test]
    fn test_show() {
        assert_eq!(format!("{:?}", SecureBytes::from("hello")), "***SECRET***".to_string());
        assert_eq!(format!("{}", SecureBytes::from("hello")), "***SECRET***".to_string());
    }

    #[test]
    fn test_comparison_zero_out_mb() {
        let mbstring1 = SecureVec::from("Hallo 🦄!");
        let mbstring2 = SecureVec::from("Hallo 🦄!");
        let mbstring3 = SecureVec::from("!🦄 ollaH");
        assert!(mbstring1 == mbstring2);
        assert!(mbstring1 != mbstring3);

        let len = mbstring1.unsecure().len();
        let mut mbstring = mbstring1.clone();
        mbstring.zero_out();
        // `zero_out` sets the `len` to 0, here we reset it to check that the bytes were zeroed
        unsafe { mbstring.content.set_len(len) }
        assert_eq!(mbstring.unsecure(), vec![0u8; len]);
    }
}
