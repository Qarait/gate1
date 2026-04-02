use crate::atom::{AtomRef, OwnedAtom};
use crate::error::Error;

pub const MAX_CONTEXT_ENTRIES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueRef<'a> {
    Bool(bool),
    Int(i64),
    Str(AtomRef<'a>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnedValue {
    Bool(bool),
    Int(i64),
    Str(OwnedAtom),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextEntry<'a> {
    key: AtomRef<'a>,
    value: ValueRef<'a>,
}

impl<'a> ContextEntry<'a> {
    pub fn new(key: AtomRef<'a>, value: ValueRef<'a>) -> Self {
        Self { key, value }
    }

    pub fn key(self) -> AtomRef<'a> {
        self.key
    }

    pub fn value(self) -> ValueRef<'a> {
        self.value
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Context<'a> {
    entries: &'a [ContextEntry<'a>],
}

impl<'a> Context<'a> {
    pub fn new(entries: &'a [ContextEntry<'a>]) -> Result<Self, Error> {
        if entries.len() > MAX_CONTEXT_ENTRIES {
            return Err(Error::TooManyContextEntries {
                limit: MAX_CONTEXT_ENTRIES,
                actual: entries.len(),
            });
        }

        for first in 0..entries.len() {
            for second in (first + 1)..entries.len() {
                if entries[first].key == entries[second].key {
                    return Err(Error::DuplicateContextKey { first, second });
                }
            }
        }

        Ok(Self { entries })
    }

    pub fn entries(&self) -> &'a [ContextEntry<'a>] {
        self.entries
    }

    pub fn get(&self, key: AtomRef<'_>) -> Option<ValueRef<'a>> {
        self.entries
            .iter()
            .find(|entry| entry.key == key)
            .map(|entry| entry.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atom::AtomRef;

    #[test]
    fn context_rejects_duplicate_keys() {
        let key = AtomRef::new("tenant").unwrap();
        let entries = [
            ContextEntry::new(key, ValueRef::Str(AtomRef::new("a").unwrap())),
            ContextEntry::new(key, ValueRef::Str(AtomRef::new("b").unwrap())),
        ];

        assert!(matches!(
            Context::new(&entries),
            Err(Error::DuplicateContextKey { first: 0, second: 1 })
        ));
    }
}
