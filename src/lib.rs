#![forbid(unsafe_code)]

//! Gate1 is a small, deterministic authorization kernel.
//!
//! Design goals:
//! - bounded evaluation
//! - zero heap allocation during `Policy::evaluate*`
//! - explicit, auditable matching semantics
//! - no hidden normalization
//! - small enough to read end-to-end
//!
//! Gate1 deliberately avoids regexes, globbing, recursive AST walking, dynamic policy loading,
//! and implicit string normalization. Construction can allocate; evaluation does not.
//!
//! See `docs/SECURITY.md` for complete security guarantees, canonicalization contracts,
//! and evaluation limits.

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
