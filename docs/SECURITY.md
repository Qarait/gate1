# Gate1 Security Guarantees & Constraints

This document outlines the detailed security posture, bounds, and behavioral contracts of the Gate1 authorization kernel.

## Canonicalization contract

Gate1 validates identifier syntax, not identifier meaning. If your system accepts mixed case, alternate numeric encodings, aliases, Unicode forms, or multiple representations for the same entity, canonicalize those before constructing Gate1 inputs.

**What the engine checks:**
- Characters: `[a-z0-9._:/-]` only; uppercase, Unicode, and whitespace are rejected at construction.
- Length: atoms are capped at `MAX_ATOM_LEN` bytes.

**What the engine does not check:**
- Whether two textually distinct atoms refer to the same logical entity.
- Whether a path, tenant prefix, or legacy ID is an alias for another.

**Examples of mismatching inputs:**
| Pair | Why they won't match |
|---|---|
| `invoice:123` vs `invoice:0123` | leading zero is a different byte sequence |
| `tenant:acme` vs `acme` | missing prefix |
| `/data/reports` vs `data/reports` | leading slash differs |
| `user:alice` vs `user:Alice` | uppercase rejected at construction; caller must lowercase |

**Security-relevant consequence:**
A `NoMatch` result means no rule matched the *exact* inputs supplied. It does not imply access is denied. If non-canonical inputs reach the engine, it returns `NoMatch`, and your application may incorrectly infer that access is safely denied. Normalize all inputs at the trust boundary.

## Fail-closed budget

Evaluation relies on a **global bounded-work-unit counter for the entire evaluation pass**. Each selector check costs 1 unit; each condition op costs 1 unit. All selector modes (`Exact`, `Prefix`, `Set`) perform bounded checks.

If the counter reaches zero, evaluation returns `Err(EvaluationBudgetExceeded)` instead of an incomplete decision. `Policy::new` computes a worst-case safe ceiling automatically.

## Default Deny (`NoMatch` risks)

`Decision::NoMatch` means no rule matched. Treating it as an implicit `Allow` downstream would be a fail-open scenario. To enforce a safe baseline, use `Policy::evaluate_deny_by_default()` to explicitly convert `NoMatch` into `Deny`.

## Prefix selector safety

`Selector::Prefix` uses a byte-exact `starts_with` check. A bare prefix like `billing` matches both `billing:invoice` and `billingplus:account`. Use a delimiter suffix (e.g., `billing:`) to make the boundary unambiguous.

## Audit Logging

`DecisionReport` reveals which rule matched. This is for **server-side audit logging only**. Exposing `matched_rule_name` to untrusted clients allows them to probe policy structure.

## MSRV Scope

Gate1's library target compiles on rustc 1.74.0. This claim applies strictly to the library crate; compiling the full repository (tests, benches, tooling) may require newer versions.
