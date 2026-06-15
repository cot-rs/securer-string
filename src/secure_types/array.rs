use core::fmt;
use std::borrow::{Borrow, BorrowMut};
use std::str::FromStr;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::SecureBox;

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
/// The contents are stored on the heap (via [`SecureBox`]) so the locked memory
/// region has a stable address: moving the `SecureArray` only moves the
/// pointer, keeping the `mlock` valid.
pub struct SecureArray<T, const LENGTH: usize>
where
    T: Copy + Zeroize,
{
    inner: SecureBox<[T; LENGTH]>,
}

impl<T, const LENGTH: usize> SecureArray<T, LENGTH>
where
    T: Copy + Zeroize,
{
    #[must_use]
    pub fn new(content: [T; LENGTH]) -> Self {
        Self {
            inner: SecureBox::new(Box::new(content)),
        }
    }

    /// Borrow the contents of the array.
    #[must_use]
    pub fn unsecure(&self) -> &[T] {
        self.borrow()
    }

    /// Mutably borrow the contents of the array.
    #[must_use]
    pub fn unsecure_mut(&mut self) -> &mut [T] {
        self.borrow_mut()
    }

    /// Overwrite the array with zeros. This is automatically called in the
    /// destructor.
    pub fn zero_out(&mut self) {
        self.inner.unsecure_mut().zeroize();
    }
}

impl<T: Copy + Zeroize, const LENGTH: usize> Clone for SecureArray<T, LENGTH> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T: Copy + Zeroize + ConstantTimeEq, const LENGTH: usize> ConstantTimeEq
    for SecureArray<T, LENGTH>
{
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.unsecure().ct_eq(other.unsecure())
    }
}

impl<T: Copy + Zeroize + ConstantTimeEq, const LENGTH: usize> PartialEq for SecureArray<T, LENGTH> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<T: Copy + Zeroize + ConstantTimeEq, const LENGTH: usize> Eq for SecureArray<T, LENGTH> {}

// Creation
impl<T, const LENGTH: usize> From<[T; LENGTH]> for SecureArray<T, LENGTH>
where
    T: Copy + Zeroize,
{
    fn from(s: [T; LENGTH]) -> Self {
        Self::new(s)
    }
}

impl<T, const LENGTH: usize> TryFrom<Vec<T>> for SecureArray<T, LENGTH>
where
    T: Copy + Zeroize,
{
    type Error = String;

    fn try_from(s: Vec<T>) -> Result<Self, Self::Error> {
        Ok(Self::new(s.try_into().map_err(|error: Vec<T>| {
            format!(
                "length mismatch: expected {LENGTH}, but got {}",
                error.len()
            )
        })?))
    }
}

impl<const LENGTH: usize> FromStr for SecureArray<u8, LENGTH> {
    type Err = std::array::TryFromSliceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(SecureArray::new(s.as_bytes().try_into()?))
    }
}

// Array item indexing
impl<T, U, const LENGTH: usize> std::ops::Index<U> for SecureArray<T, LENGTH>
where
    T: Copy + Zeroize,
    [T; LENGTH]: std::ops::Index<U>,
{
    type Output = <[T; LENGTH] as std::ops::Index<U>>::Output;

    fn index(&self, index: U) -> &Self::Output {
        std::ops::Index::index(self.inner.unsecure(), index)
    }
}

// Borrowing
impl<T, const LENGTH: usize> Borrow<[T]> for SecureArray<T, LENGTH>
where
    T: Copy + Zeroize,
{
    fn borrow(&self) -> &[T] {
        self.inner.unsecure().as_slice()
    }
}

impl<T, const LENGTH: usize> BorrowMut<[T]> for SecureArray<T, LENGTH>
where
    T: Copy + Zeroize,
{
    fn borrow_mut(&mut self) -> &mut [T] {
        self.inner.unsecure_mut().as_mut_slice()
    }
}

// Make sure sensitive information is not logged accidentally
impl<T, const LENGTH: usize> fmt::Debug for SecureArray<T, LENGTH>
where
    T: Copy + Zeroize,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SecureArray").finish_non_exhaustive()
    }
}

impl<T, const LENGTH: usize> fmt::Display for SecureArray<T, LENGTH>
where
    T: Copy + Zeroize,
{
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
        let my_sec: SecureArray<_, 5> = SecureArray::from_str("hello").unwrap();
        assert_eq!(my_sec, SecureArray::from_str("hello").unwrap());
        assert_eq!(my_sec.unsecure(), b"hello");
    }

    #[test]
    fn test_zero_out() {
        let mut my_sec: SecureArray<_, 5> = SecureArray::from_str("hello").unwrap();
        my_sec.zero_out();
        assert_eq!(my_sec.unsecure(), b"\x00\x00\x00\x00\x00");
    }

    #[test]
    fn test_comparison() {
        assert_eq!(
            SecureArray::<_, 5>::from_str("hello").unwrap(),
            SecureArray::from_str("hello").unwrap()
        );
        assert_ne!(
            SecureArray::<_, 5>::from_str("hello").unwrap(),
            SecureArray::from_str("olleh").unwrap()
        );
    }

    #[test]
    fn test_indexing() {
        let string: SecureArray<_, 5> = SecureArray::from_str("hello").unwrap();
        assert_eq!(string[0], b'h');
        assert_eq!(&string[3..5], "lo".as_bytes());
    }

    #[test]
    fn test_show() {
        assert_eq!(
            format!("{:?}", SecureArray::<_, 5>::from_str("hello").unwrap()),
            "SecureArray { .. }".to_string()
        );
        assert_eq!(
            format!("{}", SecureArray::<_, 5>::from_str("hello").unwrap()),
            "***SECRET***".to_string()
        );
    }

    #[test]
    fn test_move_keeps_contents() {
        // Regression guard for the move-after-mlock bug: moving the value must
        // preserve the contents (data lives on the heap behind a SecureBox).
        fn make() -> SecureArray<u8, 5> {
            SecureArray::from_str("hello").unwrap()
        }
        let moved = make();
        let v = [moved];
        assert_eq!(v[0].unsecure(), b"hello");
    }

    #[test]
    fn test_comparison_zero_out_multibyte() {
        let data1 = SecureArray::from([
            'H' as u32,
            'a' as u32,
            'l' as u32,
            'l' as u32,
            'o' as u32,
            ' ' as u32,
            '🦄' as u32,
            '!' as u32,
        ]);
        let data2 = SecureArray::from([
            'H' as u32,
            'a' as u32,
            'l' as u32,
            'l' as u32,
            'o' as u32,
            ' ' as u32,
            '🦄' as u32,
            '!' as u32,
        ]);
        let data3 = SecureArray::from([
            '!' as u32,
            '🦄' as u32,
            ' ' as u32,
            'o' as u32,
            'l' as u32,
            'l' as u32,
            'a' as u32,
            'H' as u32,
        ]);
        assert_eq!(data1, data2);
        assert_ne!(data1, data3);

        let mut zeroed = data1.clone();
        zeroed.zero_out();
        assert_eq!(zeroed.unsecure(), &[0u32; 8]);
    }
}
