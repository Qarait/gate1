use crate::error::Error;

/// Maximum byte length of any atom (identifier string) accepted by the engine.
pub const MAX_ATOM_LEN: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct AtomRef<'a>(&'a str);

impl<'a> AtomRef<'a> {
    /// Borrows `value` as a validated atom.
    ///
    /// Validates charset (`[a-z0-9._:/-]`) and length. Returns `Err` for any other byte,
    /// including uppercase ASCII and Unicode. No normalization is performed.
    pub fn new(value: &'a str) -> Result<Self, Error> {
        validate_atom(value)?;
        Ok(Self(value))
    }

    pub fn as_str(self) -> &'a str {
        self.0
    }
}

impl<'a> AsRef<str> for AtomRef<'a> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct OwnedAtom(String);

impl OwnedAtom {
    pub fn new(value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        validate_atom(&value)?;
        Ok(Self(value))
    }

    pub fn as_atom(&self) -> AtomRef<'_> {
        AtomRef(self.0.as_str())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl AsRef<str> for OwnedAtom {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

/// A validated principal identifier for a single evaluation call.
///
/// Syntax is validated at construction (charset `[a-z0-9._:/-]`, max [`MAX_ATOM_LEN`] bytes).
/// The engine performs **no semantic normalization**: `"user:Alice"` is rejected outright
/// (uppercase), but `"user:alice"` and a policy written for `"user:alice"` must already be
/// identical byte-for-byte. Canonicalize before constructing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Principal<'a>(AtomRef<'a>);

impl<'a> Principal<'a> {
    /// Creates a `Principal` from a string slice, validating syntax.
    ///
    /// Returns `Err` if the value is empty, exceeds [`MAX_ATOM_LEN`], or contains a
    /// disallowed character. The value is stored as-is; no normalization is applied.
    pub fn new(value: &'a str) -> Result<Self, Error> {
        Ok(Self(AtomRef::new(value)?))
    }

    pub fn as_atom(self) -> AtomRef<'a> {
        self.0
    }
}

/// A validated action identifier for a single evaluation call.
///
/// Same syntax contract as [`Principal`]: charset `[a-z0-9._:/-]`, max [`MAX_ATOM_LEN`] bytes,
/// byte-exact comparison, no normalization.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Action<'a>(AtomRef<'a>);

impl<'a> Action<'a> {
    /// Creates an `Action` from a string slice, validating syntax.
    pub fn new(value: &'a str) -> Result<Self, Error> {
        Ok(Self(AtomRef::new(value)?))
    }

    pub fn as_atom(self) -> AtomRef<'a> {
        self.0
    }
}

/// A validated resource identifier for a single evaluation call.
///
/// Same syntax contract as [`Principal`]: charset `[a-z0-9._:/-]`, max [`MAX_ATOM_LEN`] bytes,
/// byte-exact comparison, no normalization. `"invoice:123"` and `"invoice:0123"` are two
/// distinct resources as far as the engine is concerned.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Resource<'a>(AtomRef<'a>);

impl<'a> Resource<'a> {
    /// Creates a `Resource` from a string slice, validating syntax.
    pub fn new(value: &'a str) -> Result<Self, Error> {
        Ok(Self(AtomRef::new(value)?))
    }

    pub fn as_atom(self) -> AtomRef<'a> {
        self.0
    }
}

fn validate_atom(value: &str) -> Result<(), Error> {
    if value.is_empty() {
        return Err(Error::EmptyAtom);
    }

    if value.len() > MAX_ATOM_LEN {
        return Err(Error::AtomTooLong {
            limit: MAX_ATOM_LEN,
            actual: value.len(),
        });
    }

    for (index, byte) in value.bytes().enumerate() {
        let allowed = byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-');

        if !allowed {
            return Err(Error::InvalidAtomChar { index, byte });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atom_rejects_uppercase_and_unicode() {
        assert!(matches!(
            AtomRef::new("Admin"),
            Err(Error::InvalidAtomChar { .. })
        ));
        assert!(matches!(
            AtomRef::new("münchen"),
            Err(Error::InvalidAtomChar { .. })
        ));
    }

    #[test]
    fn atom_accepts_expected_characters() {
        let atom = AtomRef::new("svc.api/read:user-42").unwrap();
        assert_eq!(atom.as_str(), "svc.api/read:user-42");
    }
}
