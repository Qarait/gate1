use gate1::{
    Action, ConditionOp, ConditionProgram, Context, ContextEntry, Decision, Policy, Principal,
    Resource, Rule, ValueRef, AtomRef,
};

#[test]
fn allow_path() {
    let policy = Policy::new(vec![
        Rule::allow("allow_billing_read")
            .unwrap()
            .principal_exact("user:alice")
            .unwrap()
            .action_exact("read")
            .unwrap()
            .resource_exact("billing:invoice-7")
            .unwrap()
            .build(),
    ])
    .unwrap();

    let decision = policy
        .evaluate(
            Principal::new("user:alice").unwrap(),
            Action::new("read").unwrap(),
            Resource::new("billing:invoice-7").unwrap(),
            Context::new(&[]).unwrap(),
        )
        .unwrap();

    assert_eq!(decision, Decision::Allow);
}

#[test]
fn deny_path() {
    let policy = Policy::new(vec![
        Rule::allow("allow_ops_read")
            .unwrap()
            .action_exact("read")
            .unwrap()
            .build(),
        Rule::deny("deny_suspended")
            .unwrap()
            .action_exact("read")
            .unwrap()
            .condition(
                ConditionProgram::new(vec![ConditionOp::attr_eq_bool("suspended", true).unwrap()])
                    .unwrap(),
            )
            .build(),
    ])
    .unwrap();

    let ctx = [ContextEntry::new(
        AtomRef::new("suspended").unwrap(),
        ValueRef::Bool(true),
    )];

    let decision = policy
        .evaluate(
            Principal::new("user:bob").unwrap(),
            Action::new("read").unwrap(),
            Resource::new("cluster:one").unwrap(),
            Context::new(&ctx).unwrap(),
        )
        .unwrap();

    assert_eq!(decision, Decision::Deny);
}

#[test]
fn no_match_path() {
    let policy = Policy::new(vec![
        Rule::allow("allow_write")
            .unwrap()
            .action_exact("write")
            .unwrap()
            .build(),
    ])
    .unwrap();

    let decision = policy
        .evaluate(
            Principal::new("user:carol").unwrap(),
            Action::new("read").unwrap(),
            Resource::new("doc:5").unwrap(),
            Context::new(&[]).unwrap(),
        )
        .unwrap();

    assert_eq!(decision, Decision::NoMatch);
}

// Gate1 performs exact byte comparison of identifiers. It does not normalise
// leading zeros, aliases, path variants, or any other alternate representations.
// Canonicalisation is entirely the caller's responsibility.
//
// This test demonstrates the failure mode: a policy written for "invoice:123"
// does not match a request carrying "invoice:0123", even though the caller's
// system may treat those as the same resource. The result is NoMatch, not Deny.
// An application that interprets NoMatch as "access is safe" would be wrong.
//
// The fix belongs in the layer that constructs Gate1 inputs: strip leading zeros
// (or whatever normalisation the system requires) before calling Policy::evaluate.
#[test]
fn non_canonical_resource_does_not_match() {
    // Policy allows reading the canonical resource identifier.
    let policy = Policy::new(vec![
        Rule::allow("allow_invoice_read")
            .unwrap()
            .resource_exact("invoice:123")
            .unwrap()
            .build(),
    ])
    .unwrap();

    // Request arrives with a non-canonical form (leading zero).
    let decision = policy
        .evaluate(
            Principal::new("user:alice").unwrap(),
            Action::new("read").unwrap(),
            Resource::new("invoice:0123").unwrap(), // different byte sequence
            Context::new(&[]).unwrap(),
        )
        .unwrap();

    // NoMatch — not Deny. The rule exists but the identifier did not match.
    // This must not be interpreted as proof that access is denied or safe.
    assert_eq!(decision, Decision::NoMatch);
}

#[test]
fn prefix_selector_matches_namespace() {
    // A single rule covering the "billing:" namespace via Selector::Prefix.
    // Any resource beginning with "billing:" should match; others should not.
    let policy = Policy::new(vec![
        Rule::allow("allow_billing_namespace")
            .unwrap()
            .resource_prefix("billing:")
            .unwrap()
            .build(),
    ])
    .unwrap();

    // ── match: resource inside the namespace ──────────────────────────────
    let allow = policy
        .evaluate(
            Principal::new("user:alice").unwrap(),
            Action::new("read").unwrap(),
            Resource::new("billing:invoice-99").unwrap(),
            Context::new(&[]).unwrap(),
        )
        .unwrap();
    assert_eq!(allow, Decision::Allow);

    // ── miss: resource outside the namespace ──────────────────────────────
    let miss = policy
        .evaluate(
            Principal::new("user:alice").unwrap(),
            Action::new("read").unwrap(),
            Resource::new("reporting:summary").unwrap(),
            Context::new(&[]).unwrap(),
        )
        .unwrap();
    assert_eq!(miss, Decision::NoMatch);
}

#[test]
fn set_selector_matches_members_only() {
    // A single rule allowing only "read" and "list" actions.
    let policy = Policy::new(vec![
        Rule::allow("allow_rw")
            .unwrap()
            .action_set(vec!["read", "list"])
            .unwrap()
            .build(),
    ])
    .unwrap();

    // ── match: "read" is in the set ───────────────────────────────────────
    let allow = policy
        .evaluate(
            Principal::new("user:alice").unwrap(),
            Action::new("read").unwrap(),
            Resource::new("doc:1").unwrap(),
            Context::new(&[]).unwrap(),
        )
        .unwrap();
    assert_eq!(allow, Decision::Allow);

    // ── miss: "delete" is not in the set ─────────────────────────────────
    let miss = policy
        .evaluate(
            Principal::new("user:alice").unwrap(),
            Action::new("delete").unwrap(),
            Resource::new("doc:1").unwrap(),
            Context::new(&[]).unwrap(),
        )
        .unwrap();
    assert_eq!(miss, Decision::NoMatch);
}

#[test]
fn evaluate_deny_by_default_converts_no_match_to_deny() {
    // Policy only allows "write"; "read" has no matching rule.
    // evaluate() → NoMatch; evaluate_deny_by_default() → Deny.
    let policy = Policy::new(vec![
        Rule::allow("allow_write")
            .unwrap()
            .action_exact("write")
            .unwrap()
            .build(),
    ])
    .unwrap();

    let raw = policy
        .evaluate(
            Principal::new("user:alice").unwrap(),
            Action::new("read").unwrap(),
            Resource::new("doc:1").unwrap(),
            Context::new(&[]).unwrap(),
        )
        .unwrap();
    assert_eq!(raw, Decision::NoMatch);

    let safe = policy
        .evaluate_deny_by_default(
            Principal::new("user:alice").unwrap(),
            Action::new("read").unwrap(),
            Resource::new("doc:1").unwrap(),
            Context::new(&[]).unwrap(),
        )
        .unwrap();
    assert_eq!(safe, Decision::Deny);
}

#[test]
fn evaluate_deny_by_default_passes_through_allow() {
    let policy = Policy::new(vec![Rule::allow("allow_all").unwrap().build()]).unwrap();

    let decision = policy
        .evaluate_deny_by_default(
            Principal::new("user:alice").unwrap(),
            Action::new("read").unwrap(),
            Resource::new("doc:1").unwrap(),
            Context::new(&[]).unwrap(),
        )
        .unwrap();
    assert_eq!(decision, Decision::Allow);
}
