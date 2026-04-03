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
//! # Canonicalization contract
//!
//! Gate1 validates identifier syntax, not identifier meaning.
//!
//! **What the engine checks:** charset (`[a-z0-9._:/-]`) and byte length (`MAX_ATOM_LEN`).
//!
//! **What the engine does not check:** whether two textually distinct atoms refer to the same
//! logical entity (aliases, legacy IDs, alternate prefixes, leading zeros, etc.).
//!
//! **Security-relevant consequence:** a [`Decision::NoMatch`] result means no rule matched the
//! *exact* inputs supplied. It is not proof that access is safe. If non-canonical inputs reach
//! the engine — for example `invoice:0123` when the policy was written for `invoice:123` — the
//! engine returns `NoMatch` and the caller may incorrectly infer that access is denied. Normalize
//! all inputs to their canonical form at the trust boundary before constructing Gate1 types.
//!
//! [`Decision::NoMatch`]: policy::Decision::NoMatch

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
