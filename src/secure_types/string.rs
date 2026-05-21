use core::fmt;
use std::str::FromStr;

use crate::SecureVec;
use crate::secure_utils::memlock;

/// Wrapper for a vector that stores a valid UTF-8 string
#[derive(Clone)]
pub struct SecureString(SecureVec<u8>);

impl SecureString {
    /// Borrow the contents of the string.
    #[must_use]
    pub fn unsecure(&self) -> &str {
        // SAFETY: SecureString can only be constructed from valid UTF-8 (String or
        // &str), and the contents cannot be modified as non-UTF-8, so they
        // remain valid UTF-8.
        unsafe { std::str::from_utf8_unchecked(self.0.unsecure()) }
    }

    /// Mutably borrow the contents of the string.
    pub fn unsecure_mut(&mut self) -> &mut str {
        // SAFETY: Same as `unsecure` - contents are always valid UTF-8.
        unsafe { std::str::from_utf8_unchecked_mut(self.0.unsecure_mut()) }
    }

    /// Turn the string into a regular `String` again.
    #[must_use]
    pub fn into_unsecure(mut self) -> String {
        memlock::munlock(self.0.content.as_mut_ptr(), self.0.content.capacity());
        let content = std::mem::take(&mut self.0.content);
        std::mem::forget(self);
        // SAFETY: Same as `unsecure` - contents are always valid UTF-8.
        unsafe { String::from_utf8_unchecked(content) }
    }

    /// Overwrite the string with zeros. This is automatically called in the
    /// destructor.
    ///
    /// This also sets the length to `0`.
    pub fn zero_out(&mut self) {
        self.0.zero_out();
    }
}

impl PartialEq for SecureString {
    fn eq(&self, other: &SecureString) -> bool {
        // use constant-time implementation of SecureVec
        self.0 == other.0
    }
}

impl Eq for SecureString {}

impl fmt::Debug for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SecureString").finish_non_exhaustive()
    }
}

impl fmt::Display for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| fmt::Error)
    }
}

impl<U> From<U> for SecureString
where
    U: Into<String>,
{
    fn from(s: U) -> SecureString {
        SecureString(SecureVec::new(s.into().into_bytes()))
    }
}

impl FromStr for SecureString {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(SecureString(SecureVec::new(s.into())))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SecureString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.unsecure())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SecureString {
    fn deserialize<D>(deserializer: D) -> Result<SecureString, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SecureStringVisitor;
        impl<'de> serde::de::Visitor<'de> for SecureStringVisitor {
            type Value = SecureString;
            fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(formatter, "an utf-8 encoded string")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(SecureString::from(v.to_string()))
            }
        }
        deserializer.deserialize_string(SecureStringVisitor)
    }
}
