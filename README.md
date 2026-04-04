# gate1

`gate1` is a small Rust authorization engine for bounded, deterministic request-time policy decisions.
Policies are validated at construction time. Evaluation performs no heap allocation and fails closed if its bounded work budget is exceeded.

`gate1` is intentionally narrow. It does not provide policy distribution, role expansion, external attribute fetching, regex/glob matching, or time-based logic.

## Example

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

## Guarantees

The evaluation model is built to ensure predictable execution and reviewable logic:

- **Bounded evaluation.** Rule count, condition op count, context entries, and atom length are capped. A global evaluation budget prevents any request from evaluating unbounded graphs.
- **Zero heap allocation during evaluation.** Policy construction allocates; `Policy::evaluate*` does not.
- **ASCII-only atoms.** Identifiers are strictly limited to `[a-z0-9._:/-]` to prevent normalization bugs.
- **Typed inputs.** Values and queries use explicit typings rather than arbitrary `&str` scopes.
- **Deterministic deny-overrides.** The first matching deny overrides any allows.
- **No recursive logic.** The condition language is evaluated via a linear postfix program.
- **No `unsafe`.** The evaluator uses fixed-size stack arrays internally.

The crate intentionally keeps the rule model minimal (`Any`, `Exact`, `Prefix`, and `Set` matching).

## Scope

Gate1 establishes the execution boundary for authorization. It takes a pre-compiled policy, a flat array of context variables, and a discrete request, then returns a deterministic, zero-allocation result.

Because it operates strictly as an evaluator, it intentionally avoids:
- **Semantic normalization:** Callers must canonicalize identifiers (e.g., aliases, aliased paths) at their own trust boundary.
- **External attribute fetching:** Callers must independently populate the evaluation context before requesting a decision.
- **Dynamic policy dialects:** Callers construct bindings and conditions natively in Rust.

## Security & Release Notes

See [`docs/SECURITY.md`](docs/SECURITY.md) for detailed implementation contracts, including:
- The canonicalization contract
- Fail-closed evaluation limits
- Prefix selector delimiter safety
- `NoMatch` fallback risks
- MSRV (Minimum Supported Rust Version) constraints
