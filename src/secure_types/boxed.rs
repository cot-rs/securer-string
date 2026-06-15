use core::fmt;
use std::borrow::{Borrow, BorrowMut};
use std::mem::MaybeUninit;

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
pub struct SecureBox<T>
where
    T: Copy,
{
    // This is an `Option` to avoid UB in the destructor, outside the destructor, it is always
    // `Some(_)`
    content: Option<Box<T>>,
    /// Whether `content` is currently `mlock`ed. If `mlock` failed, `munlock`
    /// must be skipped.
    is_locked: bool,
}

impl<T> SecureBox<T>
where
    T: Copy,
{
    #[must_use]
    pub fn new(mut cont: Box<T>) -> Self {
        let is_locked = memlock::mlock(&raw mut *cont, 1).is_ok();
        SecureBox {
            content: Some(cont),
            is_locked,
        }
    }

    /// Borrow the contents of the string.
    ///
    /// # Panics
    ///
    /// Panics if the content has already been dropped.
    #[must_use]
    pub fn unsecure(&self) -> &T {
        self.content
            .as_deref()
            .expect("SecureBox content accessed after drop")
    }

    /// Mutably borrow the contents of the string.
    ///
    /// # Panics
    ///
    /// Panics if the content has already been dropped.
    #[must_use]
    pub fn unsecure_mut(&mut self) -> &mut T {
        self.content
            .as_deref_mut()
            .expect("SecureBox content accessed after drop")
    }
}

impl<T: Copy> Clone for SecureBox<T> {
    fn clone(&self) -> Self {
        Self::new(Box::new(*self.unsecure()))
    }
}

impl<T: Copy + ConstantTimeEq> ConstantTimeEq for SecureBox<T> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.unsecure().ct_eq(other.unsecure())
    }
}

impl<T: Copy + ConstantTimeEq> PartialEq for SecureBox<T> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<T: Copy + ConstantTimeEq> Eq for SecureBox<T> {}

// Delegate indexing
impl<T, U> std::ops::Index<U> for SecureBox<T>
where
    T: std::ops::Index<U> + Copy,
{
    type Output = <T as std::ops::Index<U>>::Output;

    fn index(&self, index: U) -> &Self::Output {
        std::ops::Index::index(self.unsecure(), index)
    }
}

// Borrowing
impl<T> Borrow<T> for SecureBox<T>
where
    T: Copy,
{
    fn borrow(&self) -> &T {
        self.unsecure()
    }
}
impl<T> BorrowMut<T> for SecureBox<T>
where
    T: Copy,
{
    fn borrow_mut(&mut self) -> &mut T {
        self.unsecure_mut()
    }
}

// Overwrite memory with zeros when we're done
impl<T> Drop for SecureBox<T>
where
    T: Copy,
{
    fn drop(&mut self) {
        // Make sure that the box does not need to be dropped after this function,
        // because it may see an invalid type, if `T` does not support an
        // all-zero byte-pattern Instead we manually destruct the box and only
        // handle the potentially invalid values behind the pointer
        let ptr = Box::into_raw(self.content.take().expect("SecureBox dropped twice"));

        // There is no need to worry about dropping the contents, because `T: Copy` and
        // `Copy` types cannot implement `Drop`

        // SAFETY: `ptr` was just obtained from `Box::into_raw` so it is valid, aligned,
        // and points to `size_of::<T>()` allocated bytes. Writing
        // `MaybeUninit<u8>` zeros is always valid regardless of `T`'s
        // invariants.
        unsafe {
            std::slice::from_raw_parts_mut::<MaybeUninit<u8>>(
                ptr.cast::<MaybeUninit<u8>>(),
                std::mem::size_of::<T>(),
            )
            .zeroize();
        }

        if self.is_locked {
            memlock::munlock(ptr, 1);
        }

        // Deallocate only non-zero-sized types, because otherwise it's UB
        if std::mem::size_of::<T>() != 0 {
            // SAFETY: This way to manually deallocate is advertised in the documentation of
            // `Box::into_raw`. The box was allocated with the global allocator and a layout
            // of `T` and is thus deallocated using the same allocator and
            // layout here.
            unsafe { std::alloc::dealloc(ptr.cast::<u8>(), std::alloc::Layout::new::<T>()) };
        }
    }
}

// Make sure sensitive information is not logged accidentally
impl<T> fmt::Debug for SecureBox<T>
where
    T: Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SecureBox").finish_non_exhaustive()
    }
}

impl<T> fmt::Display for SecureBox<T>
where
    T: Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| fmt::Error)
    }
}

#[cfg(test)]
mod tests {
    use std::mem::MaybeUninit;

    use zeroize::Zeroize;

    use super::SecureBox;
    use crate::test_utils::{PRIVATE_KEY_1, PRIVATE_KEY_2, Packed, Padded};

    /// Overwrite the contents with zeros.
    ///
    /// # Safety
    /// An all-zero byte-pattern must be a valid value of `T` in order for this
    /// function call to not be undefined behavior.
    unsafe fn zero_out_secure_box<T>(secure_box: &mut SecureBox<T>)
    where
        T: Copy,
    {
        unsafe {
            // SAFETY: The pointer is derived from a live `Box<T>` via mutable reference, so
            // it is valid and aligned for `size_of::<T>()` bytes. The caller
            // guarantees that an all-zero byte-pattern is a valid value of `T`.
            std::slice::from_raw_parts_mut::<MaybeUninit<u8>>(
                std::ptr::from_mut::<T>(secure_box.unsecure_mut()).cast::<MaybeUninit<u8>>(),
                std::mem::size_of::<T>(),
            )
            .zeroize();
        }
    }

    #[test]
    fn test_secure_box() {
        let key_1 = SecureBox::new(Box::new(PRIVATE_KEY_1));
        let key_2 = SecureBox::new(Box::new(PRIVATE_KEY_2));
        let key_3 = SecureBox::new(Box::new(PRIVATE_KEY_1));
        assert_eq!(key_1, key_1);
        assert_ne!(key_1, key_2);
        assert_ne!(key_2, key_3);
        assert_eq!(key_1, key_3);

        let mut final_key = key_1.clone();
        unsafe {
            zero_out_secure_box(&mut final_key);
        }
        assert_eq!(final_key.unsecure().0, [0; 32]);
    }

    #[test]
    fn test_repr_c_with_padding() {
        assert_eq!(std::mem::size_of::<Padded>(), 4); // 1 + 1 (pad) + 2

        let sec_a = SecureBox::new(Box::new(Padded { x: 1, y: 2 }));
        let sec_b = SecureBox::new(Box::new(Padded { x: 1, y: 2 }));
        assert_eq!(sec_a, sec_b);

        let sec_c = SecureBox::new(Box::new(Padded { x: 1, y: 3 }));
        assert_ne!(sec_a, sec_c);

        let sec_d = SecureBox::new(Box::new(Padded { x: 2, y: 2 }));
        assert_ne!(sec_a, sec_d);
    }

    #[test]
    fn test_repr_c_packed() {
        assert_eq!(std::mem::size_of::<Packed>(), 3);

        let sec_a = SecureBox::new(Box::new(Packed { x: 42, y: 1000 }));
        let sec_b = SecureBox::new(Box::new(Packed { x: 42, y: 1000 }));
        let sec_c = SecureBox::new(Box::new(Packed { x: 42, y: 1001 }));
        let sec_d = SecureBox::new(Box::new(Packed { x: 43, y: 1000 }));

        assert_eq!(sec_a, sec_b);
        assert_ne!(sec_a, sec_c);
        assert_ne!(sec_a, sec_d);
    }
}
