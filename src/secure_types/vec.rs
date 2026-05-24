use core::fmt;
use std::borrow::{Borrow, BorrowMut};
use std::str::FromStr;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::secure_utils::memlock;

/// A data type suitable for storing sensitive information such as passwords and
/// private keys in memory, that implements:
///
/// - Automatic zeroing in `Drop`
/// - Constant time comparison in `PartialEq` (does not short circuit on the
///   first different character; but terminates instantly if strings have
///   different length)
/// - Outputting `***SECRET***` to prevent leaking secrets into logs in
///   `fmt::Debug` and `fmt::Display`
/// - Automatic `mlock` to protect against leaking into swap (any unix)
/// - Automatic `madvise(MADV_NOCORE/MADV_DONTDUMP)` to protect against leaking
///   into core dumps (FreeBSD, DragonflyBSD, Linux)
///
/// `PartialEq` and `Eq` are only implemented when `T: ConstantTimeEq`. The
/// safety of comparisons with respect to padding bytes depends on the
/// `ConstantTimeEq` implementation of `T`.
///
/// Be careful with `SecureBytes::from`: if you have a borrowed string, it will
/// be copied. Use `SecureBytes::new` if you have a `Vec<u8>`.
pub struct SecureVec<T>
where
    T: Copy + Zeroize,
{
    pub(crate) content: Vec<T>,
    /// Whether `content` is currently `mlock`ed. If `mlock` failed, `munlock`
    /// must be skipped.
    pub(crate) is_locked: bool,
}

/// Type alias for a vector that stores just bytes
pub type SecureBytes = SecureVec<u8>;

impl<T> SecureVec<T>
where
    T: Copy + Zeroize,
{
    #[must_use]
    pub fn new(mut cont: Vec<T>) -> Self {
        let is_locked = memlock::mlock(cont.as_mut_ptr(), cont.capacity());
        SecureVec {
            content: cont,
            is_locked,
        }
    }

    /// Borrow the contents of the string.
    #[must_use]
    pub fn unsecure(&self) -> &[T] {
        self.borrow()
    }

    /// Mutably borrow the contents of the string.
    pub fn unsecure_mut(&mut self) -> &mut [T] {
        self.borrow_mut()
    }

    /// Resizes the `SecureVec` in-place so that len is equal to `new_len`.
    ///
    /// If `new_len` is smaller the inner vector is truncated.
    /// If `new_len` is larger the inner vector will grow, placing `value` in
    /// all new cells.
    ///
    /// This ensures that the new memory region is secured if reallocation
    /// occurs.
    ///
    /// Similar to [`Vec::resize`](https://doc.rust-lang.org/std/vec/struct.Vec.html#method.resize)
    pub fn resize(&mut self, new_len: usize, value: T) {
        // Trucnate if shorter or same length
        if new_len <= self.content.len() {
            self.content.truncate(new_len);
            return;
        }

        // Allocate new vector, copy old data into it
        let mut new_vec = vec![value; new_len];
        let new_is_locked = memlock::mlock(new_vec.as_mut_ptr(), new_vec.capacity());
        new_vec[0..self.content.len()].copy_from_slice(&self.content);

        // Securely clear old vector, replace with new vector
        self.zero_out();
        if self.is_locked {
            memlock::munlock(self.content.as_mut_ptr(), self.content.capacity());
        }
        self.content = new_vec;
        self.is_locked = new_is_locked;
    }

    /// Overwrite the string with zeros. This is automatically called in the
    /// destructor.
    ///
    /// This also sets the length to `0`.
    pub fn zero_out(&mut self) {
        self.content.zeroize();
    }
}

impl<T: Copy + Zeroize> Clone for SecureVec<T> {
    fn clone(&self) -> Self {
        Self::new(self.content.clone())
    }
}

impl<T: Copy + Zeroize + ConstantTimeEq> ConstantTimeEq for SecureVec<T> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.content.ct_eq(&other.content)
    }
}

impl<T: Copy + Zeroize + ConstantTimeEq> PartialEq for SecureVec<T> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<T: Copy + Zeroize + ConstantTimeEq> Eq for SecureVec<T> {}

// Creation
impl<T, U> From<U> for SecureVec<T>
where
    U: Into<Vec<T>>,
    T: Copy + Zeroize,
{
    fn from(s: U) -> SecureVec<T> {
        SecureVec::new(s.into())
    }
}

impl FromStr for SecureVec<u8> {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(SecureVec::new(s.into()))
    }
}

// Vec item indexing
impl<T, U> std::ops::Index<U> for SecureVec<T>
where
    T: Copy + Zeroize,
    Vec<T>: std::ops::Index<U>,
{
    type Output = <Vec<T> as std::ops::Index<U>>::Output;

    fn index(&self, index: U) -> &Self::Output {
        std::ops::Index::index(&self.content, index)
    }
}

// Borrowing
impl<T> Borrow<[T]> for SecureVec<T>
where
    T: Copy + Zeroize,
{
    fn borrow(&self) -> &[T] {
        self.content.borrow()
    }
}

impl<T> BorrowMut<[T]> for SecureVec<T>
where
    T: Copy + Zeroize,
{
    fn borrow_mut(&mut self) -> &mut [T] {
        self.content.borrow_mut()
    }
}

// Overwrite memory with zeros when we're done
impl<T> Drop for SecureVec<T>
where
    T: Copy + Zeroize,
{
    fn drop(&mut self) {
        self.zero_out();
        if self.is_locked {
            memlock::munlock(self.content.as_mut_ptr(), self.content.capacity());
        }
    }
}

// Make sure sensitive information is not logged accidentally
impl<T> fmt::Debug for SecureVec<T>
where
    T: Copy + Zeroize,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SecureVec").finish_non_exhaustive()
    }
}

impl<T> fmt::Display for SecureVec<T>
where
    T: Copy + Zeroize,
{
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
        // `zero_out` sets the `len` to 0, here we reset it to check that the bytes were
        // zeroed
        unsafe {
            my_sec.content.set_len(5);
        }
        assert_eq!(my_sec.unsecure(), b"\x00\x00\x00\x00\x00");
    }

    #[test]
    fn test_resize() {
        let mut my_sec = SecureVec::from([0, 1]);
        assert_eq!(my_sec.unsecure().len(), 2);
        my_sec.resize(1, 0);
        assert_eq!(my_sec.unsecure().len(), 1);
        my_sec.resize(16, 2);
        assert_eq!(
            my_sec.unsecure(),
            &[0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]
        );
    }

    #[test]
    fn test_comparison() {
        assert_eq!(SecureBytes::from("hello"), SecureBytes::from("hello"));
        assert_ne!(SecureBytes::from("hello"), SecureBytes::from("yolo"));
        assert_ne!(SecureBytes::from("hello"), SecureBytes::from("olleh"));
        assert_ne!(SecureBytes::from("hello"), SecureBytes::from("helloworld"));
        assert_ne!(SecureBytes::from("hello"), SecureBytes::from(""));
    }

    #[test]
    fn test_indexing() {
        let string = SecureBytes::from("hello");
        assert_eq!(string[0], b'h');
        assert_eq!(&string[3..5], "lo".as_bytes());
    }

    #[test]
    fn test_show() {
        assert_eq!(
            format!("{:?}", SecureBytes::from("hello")),
            "SecureVec { .. }".to_string()
        );
        assert_eq!(
            format!("{}", SecureBytes::from("hello")),
            "***SECRET***".to_string()
        );
    }

    #[test]
    fn test_comparison_zero_out_mb() {
        let mbstring1 = SecureVec::from(vec![
            'H' as u32,
            'a' as u32,
            'l' as u32,
            'l' as u32,
            'o' as u32,
            ' ' as u32,
            '🦄' as u32,
            '!' as u32,
        ]);
        let mbstring2 = SecureVec::from(vec![
            'H' as u32,
            'a' as u32,
            'l' as u32,
            'l' as u32,
            'o' as u32,
            ' ' as u32,
            '🦄' as u32,
            '!' as u32,
        ]);
        let mbstring3 = SecureVec::from(vec![
            '!' as u32,
            '🦄' as u32,
            ' ' as u32,
            'o' as u32,
            'l' as u32,
            'l' as u32,
            'a' as u32,
            'H' as u32,
        ]);
        assert_eq!(mbstring1, mbstring2);
        assert_ne!(mbstring1, mbstring3);

        let mut mbstring = mbstring1.clone();
        mbstring.zero_out();
        // `zero_out` sets the `len` to 0, here we reset it to check that the bytes were
        // zeroed
        unsafe {
            mbstring.content.set_len(8);
        }
        assert_eq!(mbstring.unsecure(), &[0u32; 8]);
    }
}
