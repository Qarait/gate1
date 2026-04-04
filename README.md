# gate1

`gate1` is a small authorization kernel for Rust.

It is intentionally narrow in scope: build a policy once, validate it up front, then evaluate request-time decisions with deterministic, bounded behavior.

```rust
use gate1::{
    Action, AtomRef, ConditionOp, ConditionProgram, Context, ContextEntry, Policy, Principal,
    Resource, Rule, ValueRef,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let condition = ConditionProgram::new(vec![
        ConditionOp::attr_eq_str("tenant", "acme")?,
        ConditionOp::attr_eq_bool("mfa", true)?,
        ConditionOp::and(),
    ])?;

    let policy = Policy::new(vec![
        Rule::allow("allow_invoice_read")?
            .principal_exact("user:alice")?
            .action_exact("read")?
            .resource_exact("invoice:123")?
            .condition(condition)
            .build(),
        Rule::deny("deny_suspended")?
            .condition(ConditionProgram::new(vec![
                ConditionOp::attr_eq_bool("suspended", true)?,
            ])?)
            .build(),
    ])?;

    let entries = [
        ContextEntry::new(
            AtomRef::new("tenant")?,
            ValueRef::Str(AtomRef::new("acme")?),
        ),
        ContextEntry::new(AtomRef::new("mfa")?, ValueRef::Bool(true)),
    ];

    let decision = policy.evaluate_deny_by_default(
        Principal::new("user:alice")?,
        Action::new("read")?,
        Resource::new("invoice:123")?,
        Context::new(&entries)?,
    )?;

    println!("{decision:?}");
    Ok(())
}
```

## What it is

`gate1` is a small Rust library for bounded authorization checks. Policies are validated at construction; evaluation is deterministic and does not allocate.

The project keeps the same core shape:

```text
Result<Decision> = evaluate(principal, action, resource, context)
```

The implementation stays deliberately small to remain straightforward to audit.

## Security posture

The design makes a few opinionated choices.

- **No hidden normalization.** The engine validates identifier syntax (charset and length) and stops there. It does not fold case, collapse path aliases, expand prefixes, or otherwise reconcile equivalent representations. Inputs that are semantically identical but textually different will not match each other.
- **ASCII-only atoms.** Request and policy strings are restricted to `[a-z0-9._:/-]` and a fixed maximum length.
- **Typed request inputs.** `Principal`, `Action`, and `Resource` are distinct types instead of plain `&str`.
- **Bounded evaluation.** Rule count, condition op count, condition depth, context entries, and atom length are capped.
- **Fail-closed budget.** The budget is a **global bounded-work-unit counter for the entire evaluation pass**, not a per-rule limit. Each selector check (principal, action, resource) costs 1 unit; each condition op costs 1 unit. `Exact` is a single comparison; `Prefix` scans bytes up to atom length; `Set` performs up to `MAX_SELECTOR_SET` comparisons — all bounded, so 1 unit per selector check is a conservative but safe accounting. Consumption is path-dependent — rules whose selectors fail early charge fewer units than rules that reach a full condition program. If the counter reaches zero, evaluation returns `Err(EvaluationBudgetExceeded)` instead of returning an incomplete decision. `Policy::new` computes a worst-case safe ceiling automatically; `Policy::with_budget` is an advanced override for callers who have measured their own workload.
- **Deterministic deny-overrides.** The first matching deny wins. Allows are remembered and returned only if no deny matches later.
- **No `unsafe`.** The crate forbids `unsafe_code` and keeps the evaluator on fixed-size stack storage.
- **Zero heap allocation during evaluation.** Policy construction allocates. `Policy::evaluate*` does not.

## Design limits

The primary goal is to constrain the authorization problem until the implementation becomes reviewable. To maintain this discipline, the library:

- drops `MaybeUninit` from the hot path in favor of plain stack arrays,
- rejects invalid identifier syntax and performs no semantic normalization,
- rejects duplicate context keys,
- uses an explicit evaluation budget,
- exposes `DecisionReport` so callers can log which rule matched without allocating an explanation string. `DecisionReport` is for server-side audit logging only; do not forward `matched_rule_name` or `matched_rule_index` to untrusted callers, as they reveal policy structure and can be used to probe rule boundaries.

The crate intentionally supports a small rule model and leaves policy management outside the library.

## Rule model

A rule contains:

- `effect`: `Allow` or `Deny`
- `principal` selector: `Any`, `Exact`, `Prefix`, or `Set`
- `action` selector: `Any`, `Exact`, `Prefix`, or `Set`
- `resource` selector: `Any`, `Exact`, `Prefix`, or `Set`
- optional condition program in postfix form

`Exact` performs byte-exact equality. `Prefix` performs a byte-exact `starts_with` check
(see the [prefix safety note](#prefix-selector-safety) below). `Set` tests byte-exact membership
against a fixed list of up to `MAX_SELECTOR_SET` validated atoms.

The condition language is intentionally small:

- `AttrPresent`
- `AttrEqBool`
- `AttrEqInt`
- `AttrEqStr`
- `True`
- `False`
- `Not`
- `And`
- `Or`

Using postfix form keeps validation and evaluation non-recursive.

## Non-goals

`gate1` does not try to solve:

- distributed policy management,
- user-friendly policy authoring,
- regex, glob, or general query-language matching (Prefix and Set are the intentional limit),
- external attribute fetching,
- role expansion,
- time-based conditions,
- multi-tenant policy storage,
- cryptographic attestation of inputs.

Those belong outside the core.

## Security & Operations

See [`docs/SECURITY.md`](docs/SECURITY.md) for detailed information on:
- The canonicalization contract and input taxonomy
- Fail-closed evaluation limits and bounds computation
- Prefix selector safety
- Strict `NoMatch` behavior and fallback mapping
- MSRV (Minimum Supported Rust Version) constraints
