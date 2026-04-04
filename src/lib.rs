#![forbid(unsafe_code)]

//! Bounded authorization evaluation for Rust.
//!
//! Policies are validated at construction time. Evaluation is deterministic,
//! allocation-free, and byte-exact.
//!
//! Callers must canonicalize identifiers before constructing Gate1 inputs.
//! See `docs/SECURITY.md` for explicit API contracts and evaluation limits.

pub mod atom;
pub mod context;
pub mod error;
pub mod policy;

pub use atom::{Action, AtomRef, OwnedAtom, Principal, Resource, MAX_ATOM_LEN};
pub use context::{Context, ContextEntry, OwnedValue, ValueRef, MAX_CONTEXT_ENTRIES};
pub use error::Error;
pub use policy::{
    ConditionOp, ConditionProgram, Decision, DecisionReport, Effect, Policy, Rule, Selector,
    MAX_CONDITION_DEPTH, MAX_CONDITION_OPS, MAX_RULES, MAX_SELECTOR_SET,
};
