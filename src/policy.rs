use crate::atom::{Action, AtomRef, OwnedAtom, Principal, Resource};
use crate::context::{Context, ValueRef};
use crate::error::Error;

pub const MAX_RULES: usize = 64;
pub const MAX_CONDITION_OPS: usize = 32;
pub const MAX_CONDITION_DEPTH: usize = 8;
/// Maximum number of values in a [`Selector::Set`]. Keeps set iteration bounded during evaluation.
pub const MAX_SELECTOR_SET: usize = 16;
const MAX_CONDITION_STACK: usize = MAX_CONDITION_OPS;

/// The intended outcome of a rule: permit or deny access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Effect {
    Allow,
    Deny,
}

/// The outcome of a single `Policy::evaluate` call.
///
/// `NoMatch` means no rule in the policy matched the supplied inputs. It does **not** mean
/// access is denied or safe — it means the policy had no opinion. Applications must treat
/// `NoMatch` as a failure to authorize, not as implicit denial.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    /// A matching allow rule was found and no deny rule overrode it.
    Allow,
    /// A matching deny rule was found; deny-overrides is always applied.
    Deny,
    /// No rule matched the exact inputs supplied. Not equivalent to `Deny`.
    /// The most common cause is non-canonical inputs — see the crate-level canonicalization
    /// contract.
    NoMatch,
}

/// The outcome of a policy evaluation, including which rule matched.
///
/// `DecisionReport` is intended for **internal audit logging and debugging only**.
/// Do not expose it, or any of its fields, to untrusted callers.
///
/// `matched_rule_name` and `matched_rule_index` reveal the internal structure of your policy.
/// A requester who can observe which rule fired — or infer it from an error or side-channel —
/// can probe the policy to discover rule boundaries and craft inputs that land in a desired branch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecisionReport<'a> {
    /// The final allow/deny/no-match verdict.
    pub decision: Decision,
    /// Index of the matched rule within the policy's rule list.
    ///
    /// **Do not return to untrusted callers.** Rule indices reveal policy structure and order.
    pub matched_rule_index: Option<usize>,
    /// Name of the matched rule as supplied at construction time.
    ///
    /// **Do not return to untrusted callers.** Rule names reveal policy structure and intent.
    pub matched_rule_name: Option<&'a str>,
}

/// Matches a request field against a policy expectation.
///
/// `Any` matches every value. `Exact` and `Prefix` validate the stored value's syntax at
/// construction time. No case folding or semantic normalization is performed by any variant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Selector {
    /// Matches any value unconditionally.
    Any,
    /// Matches one specific, syntax-validated identifier. Comparison is byte-exact.
    Exact(OwnedAtom),
    /// Matches any value that starts with the stored prefix string. Byte-exact prefix check;
    /// no normalization is performed.
    Prefix(OwnedAtom),
    /// Matches any value that is a member of a fixed, syntax-validated set.
    /// The set is bounded by [`MAX_SELECTOR_SET`]. Membership is checked by byte-exact equality.
    Set(Vec<OwnedAtom>),
}

impl Selector {
    /// Creates a selector that matches any value.
    pub fn any() -> Self {
        Self::Any
    }

    /// Creates a selector that matches exactly `value`.
    ///
    /// Validates charset (`[a-z0-9._:/-]`) and length at construction time.
    /// No semantic normalization is performed — `"invoice:123"` and `"invoice:0123"` produce
    /// two distinct selectors that will never match each other.
    pub fn exact(value: impl Into<String>) -> Result<Self, Error> {
        Ok(Self::Exact(OwnedAtom::new(value)?))
    }

    /// Creates a selector that matches any value beginning with `prefix`.
    ///
    /// `prefix` is syntax-validated (charset `[a-z0-9._:/-]`, max [`MAX_ATOM_LEN`] bytes).
    /// Matching is byte-exact: `"billing:"` matches `"billing:invoice-1"` but not `"Billing:"`.
    /// No normalization is performed.
    ///
    /// [`MAX_ATOM_LEN`]: crate::atom::MAX_ATOM_LEN
    pub fn prefix(prefix: impl Into<String>) -> Result<Self, Error> {
        Ok(Self::Prefix(OwnedAtom::new(prefix)?))
    }

    /// Creates a selector that matches any value in the given set.
    ///
    /// Each element is syntax-validated at construction time. The set must be non-empty and
    /// may contain at most [`MAX_SELECTOR_SET`] elements. Membership is tested by byte-exact
    /// equality; no normalization is performed.
    pub fn set(values: Vec<impl Into<String>>) -> Result<Self, Error> {
        if values.is_empty() {
            return Err(Error::EmptySelectorSet);
        }
        if values.len() > MAX_SELECTOR_SET {
            return Err(Error::SelectorSetTooLarge {
                limit: MAX_SELECTOR_SET,
                actual: values.len(),
            });
        }
        let atoms = values
            .into_iter()
            .map(|v| OwnedAtom::new(v))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::Set(atoms))
    }

    fn matches(&self, candidate: AtomRef<'_>) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(expected) => expected.as_atom() == candidate,
            Self::Prefix(prefix) => candidate.as_str().starts_with(prefix.as_str()),
            Self::Set(set) => set.iter().any(|item| item.as_atom() == candidate),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConditionOp {
    AttrPresent { key: OwnedAtom },
    AttrEqBool { key: OwnedAtom, value: bool },
    AttrEqInt { key: OwnedAtom, value: i64 },
    AttrEqStr { key: OwnedAtom, value: OwnedAtom },
    True,
    False,
    Not,
    And,
    Or,
}

impl ConditionOp {
    pub fn attr_present(key: impl Into<String>) -> Result<Self, Error> {
        Ok(Self::AttrPresent {
            key: OwnedAtom::new(key)?,
        })
    }

    pub fn attr_eq_bool(key: impl Into<String>, value: bool) -> Result<Self, Error> {
        Ok(Self::AttrEqBool {
            key: OwnedAtom::new(key)?,
            value,
        })
    }

    pub fn attr_eq_int(key: impl Into<String>, value: i64) -> Result<Self, Error> {
        Ok(Self::AttrEqInt {
            key: OwnedAtom::new(key)?,
            value,
        })
    }

    pub fn attr_eq_str(
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, Error> {
        Ok(Self::AttrEqStr {
            key: OwnedAtom::new(key)?,
            value: OwnedAtom::new(value)?,
        })
    }

    pub fn always_true() -> Self {
        Self::True
    }

    pub fn always_false() -> Self {
        Self::False
    }

    pub fn not() -> Self {
        Self::Not
    }

    pub fn and() -> Self {
        Self::And
    }

    pub fn or() -> Self {
        Self::Or
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConditionProgram {
    ops: Vec<ConditionOp>,
}

impl ConditionProgram {
    /// Builds and validates a condition program from a sequence of postfix ops.
    ///
    /// Validation checks: non-empty, within [`MAX_CONDITION_OPS`], within [`MAX_CONDITION_DEPTH`],
    /// and that the op sequence reduces to exactly one value on the stack. All structural errors
    /// are returned at construction time; `evaluate` will not encounter them.
    pub fn new(ops: Vec<ConditionOp>) -> Result<Self, Error> {
        validate_condition_ops(&ops)?;
        Ok(Self { ops })
    }

    pub fn ops(&self) -> &[ConditionOp] {
        self.ops.as_slice()
    }
}

/// A single authorization rule: an effect, three selectors, and an optional condition.
///
/// Rules are constructed via [`Rule::allow`] or [`Rule::deny`] and are immutable once built.
/// Selector defaults are `Any`; narrow them with the builder methods before calling `build()`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rule {
    name: OwnedAtom,
    effect: Effect,
    principal: Selector,
    action: Selector,
    resource: Selector,
    condition: Option<ConditionProgram>,
}

impl Rule {
    /// Starts building an allow rule with the given name.
    ///
    /// `name` is syntax-validated (charset `[a-z0-9._:/-]`, max [`MAX_ATOM_LEN`] bytes).
    /// Rule names must be unique within a [`Policy`]; duplicates are rejected at `Policy::new`.
    /// All three selectors default to `Any`.
    pub fn allow(name: impl Into<String>) -> Result<RuleBuilder, Error> {
        RuleBuilder::new(name, Effect::Allow)
    }

    /// Starts building a deny rule with the given name.
    ///
    /// See [`Rule::allow`] for name constraints. Deny rules apply the same selector and
    /// condition logic, but `Effect::Deny` always overrides any matching allow rule.
    pub fn deny(name: impl Into<String>) -> Result<RuleBuilder, Error> {
        RuleBuilder::new(name, Effect::Deny)
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn effect(&self) -> Effect {
        self.effect
    }

    pub fn condition(&self) -> Option<&ConditionProgram> {
        self.condition.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleBuilder {
    name: OwnedAtom,
    effect: Effect,
    principal: Selector,
    action: Selector,
    resource: Selector,
    condition: Option<ConditionProgram>,
}

impl RuleBuilder {
    fn new(name: impl Into<String>, effect: Effect) -> Result<Self, Error> {
        Ok(Self {
            name: OwnedAtom::new(name)?,
            effect,
            principal: Selector::Any,
            action: Selector::Any,
            resource: Selector::Any,
            condition: None,
        })
    }

    pub fn principal_any(mut self) -> Self {
        self.principal = Selector::Any;
        self
    }

    pub fn principal_exact(mut self, value: impl Into<String>) -> Result<Self, Error> {
        self.principal = Selector::exact(value)?;
        Ok(self)
    }

    pub fn principal_prefix(mut self, prefix: impl Into<String>) -> Result<Self, Error> {
        self.principal = Selector::prefix(prefix)?;
        Ok(self)
    }

    pub fn principal_set(mut self, values: Vec<impl Into<String>>) -> Result<Self, Error> {
        self.principal = Selector::set(values)?;
        Ok(self)
    }

    pub fn action_any(mut self) -> Self {
        self.action = Selector::Any;
        self
    }

    pub fn action_exact(mut self, value: impl Into<String>) -> Result<Self, Error> {
        self.action = Selector::exact(value)?;
        Ok(self)
    }

    pub fn action_prefix(mut self, prefix: impl Into<String>) -> Result<Self, Error> {
        self.action = Selector::prefix(prefix)?;
        Ok(self)
    }

    pub fn action_set(mut self, values: Vec<impl Into<String>>) -> Result<Self, Error> {
        self.action = Selector::set(values)?;
        Ok(self)
    }

    pub fn resource_any(mut self) -> Self {
        self.resource = Selector::Any;
        self
    }

    pub fn resource_exact(mut self, value: impl Into<String>) -> Result<Self, Error> {
        self.resource = Selector::exact(value)?;
        Ok(self)
    }

    pub fn resource_prefix(mut self, prefix: impl Into<String>) -> Result<Self, Error> {
        self.resource = Selector::prefix(prefix)?;
        Ok(self)
    }

    pub fn resource_set(mut self, values: Vec<impl Into<String>>) -> Result<Self, Error> {
        self.resource = Selector::set(values)?;
        Ok(self)
    }

    pub fn condition(mut self, condition: ConditionProgram) -> Self {
        self.condition = Some(condition);
        self
    }

    pub fn build(self) -> Rule {
        Rule {
            name: self.name,
            effect: self.effect,
            principal: self.principal,
            action: self.action,
            resource: self.resource,
            condition: self.condition,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Policy {
    rules: Vec<Rule>,
    evaluation_budget: u32,
}

impl Policy {
    /// Constructs a policy with an automatically computed evaluation budget.
    ///
    /// The budget is set to the worst-case number of units that could be consumed if every rule
    /// is tested against every selector and every condition op is executed. This is the
    /// recommended constructor for most callers.
    pub fn new(rules: Vec<Rule>) -> Result<Self, Error> {
        validate_rules(&rules)?;
        let budget = default_budget_for(&rules);
        Ok(Self {
            rules,
            evaluation_budget: budget,
        })
    }

    /// Constructs a policy with an explicit evaluation budget.
    ///
    /// **This is an advanced API.** Most callers should use [`Policy::new`], which computes a
    /// safe worst-case budget automatically.
    ///
    /// # Budget semantics
    ///
    /// The budget is a **global unit counter for the entire evaluation pass**, not a per-rule
    /// limit. It is shared across every rule tested during a single call to `evaluate` or
    /// `evaluate_with_report`.
    ///
    /// Each of the following operations consumes **1 unit**:
    ///
    /// - Testing a principal, action, or resource selector (3 units per rule checked).
    /// - Executing one condition op.
    ///
    /// Consumption is **path-dependent**: rules whose selectors fail early charge fewer units
    /// than rules whose conditions are fully evaluated. In the worst case every rule matches all
    /// three selectors and evaluates its full condition program.
    ///
    /// If the budget is exhausted before evaluation completes, `evaluate` returns
    /// [`Error::EvaluationBudgetExceeded`] rather than returning a potentially incomplete
    /// decision. Setting `max_eval_units` too low can cause spurious budget errors on valid
    /// requests; setting it too high weakens the fail-closed guarantee.
    ///
    /// [`Error::EvaluationBudgetExceeded`]: crate::error::Error::EvaluationBudgetExceeded
    pub fn with_budget(rules: Vec<Rule>, max_eval_units: u32) -> Result<Self, Error> {
        validate_rules(&rules)?;

        if max_eval_units == 0 {
            return Err(Error::ZeroEvaluationBudget);
        }

        Ok(Self {
            rules,
            evaluation_budget: max_eval_units,
        })
    }

    pub fn rules(&self) -> &[Rule] {
        self.rules.as_slice()
    }

    pub fn evaluation_budget(&self) -> u32 {
        self.evaluation_budget
    }

    pub fn evaluate(
        &self,
        principal: Principal<'_>,
        action: Action<'_>,
        resource: Resource<'_>,
        context: Context<'_>,
    ) -> Result<Decision, Error> {
        Ok(self
            .evaluate_with_report(principal, action, resource, context)?
            .decision)
    }

    /// Evaluates the policy and converts [`Decision::NoMatch`] to [`Decision::Deny`].
    ///
    /// This is the **recommended entry point for most applications**. A `NoMatch` result means
    /// the policy had no opinion; treating it as `Allow` would be fail-open. This method makes
    /// the safe default explicit so callers do not have to remember to handle `NoMatch` themselves.
    ///
    /// The result is either `Ok(Allow)`, `Ok(Deny)`, or `Err(...)`. `NoMatch` is never returned.
    pub fn evaluate_deny_by_default(
        &self,
        principal: Principal<'_>,
        action: Action<'_>,
        resource: Resource<'_>,
        context: Context<'_>,
    ) -> Result<Decision, Error> {
        match self.evaluate(principal, action, resource, context)? {
            Decision::NoMatch => Ok(Decision::Deny),
            other => Ok(other),
        }
    }

    pub fn evaluate_with_report<'a>(
        &'a self,
        principal: Principal<'_>,
        action: Action<'_>,
        resource: Resource<'_>,
        context: Context<'_>,
    ) -> Result<DecisionReport<'a>, Error> {
        let mut budget = self.evaluation_budget;
        let mut first_allow: Option<(usize, &'a str)> = None;

        for (index, rule) in self.rules.iter().enumerate() {
            if !matches_selector(
                &rule.principal,
                principal.as_atom(),
                &mut budget,
                self.evaluation_budget,
            )? {
                continue;
            }

            if !matches_selector(
                &rule.action,
                action.as_atom(),
                &mut budget,
                self.evaluation_budget,
            )? {
                continue;
            }

            if !matches_selector(
                &rule.resource,
                resource.as_atom(),
                &mut budget,
                self.evaluation_budget,
            )? {
                continue;
            }

            if let Some(condition) = rule.condition.as_ref() {
                if !evaluate_condition(condition, context, &mut budget, self.evaluation_budget)? {
                    continue;
                }
            }

            match rule.effect {
                Effect::Deny => {
                    return Ok(DecisionReport {
                        decision: Decision::Deny,
                        matched_rule_index: Some(index),
                        matched_rule_name: Some(rule.name.as_str()),
                    });
                }
                Effect::Allow => {
                    if first_allow.is_none() {
                        first_allow = Some((index, rule.name.as_str()));
                    }
                }
            }
        }

        if let Some((index, name)) = first_allow {
            return Ok(DecisionReport {
                decision: Decision::Allow,
                matched_rule_index: Some(index),
                matched_rule_name: Some(name),
            });
        }

        Ok(DecisionReport {
            decision: Decision::NoMatch,
            matched_rule_index: None,
            matched_rule_name: None,
        })
    }
}

fn default_budget_for(rules: &[Rule]) -> u32 {
    let mut total = 0u32;

    for rule in rules {
        total += 3;
        if let Some(condition) = rule.condition.as_ref() {
            total += condition.ops.len() as u32;
        }
    }

    total.max(1)
}

fn validate_rules(rules: &[Rule]) -> Result<(), Error> {
    if rules.len() > MAX_RULES {
        return Err(Error::TooManyRules {
            limit: MAX_RULES,
            actual: rules.len(),
        });
    }

    for first in 0..rules.len() {
        for second in (first + 1)..rules.len() {
            if rules[first].name == rules[second].name {
                return Err(Error::DuplicateRuleName { first, second });
            }
        }
    }

    Ok(())
}

fn matches_selector(
    selector: &Selector,
    candidate: AtomRef<'_>,
    budget: &mut u32,
    budget_limit: u32,
) -> Result<bool, Error> {
    charge(budget, 1, budget_limit)?;
    Ok(selector.matches(candidate))
}

fn evaluate_condition(
    program: &ConditionProgram,
    context: Context<'_>,
    budget: &mut u32,
    budget_limit: u32,
) -> Result<bool, Error> {
    let mut stack = [false; MAX_CONDITION_STACK];
    let mut len = 0usize;

    for (index, op) in program.ops.iter().enumerate() {
        charge(budget, 1, budget_limit)?;

        match op {
            ConditionOp::AttrPresent { key } => {
                stack[len] = context.get(key.as_atom()).is_some();
                len += 1;
            }
            ConditionOp::AttrEqBool { key, value } => {
                stack[len] = matches!(context.get(key.as_atom()), Some(ValueRef::Bool(actual)) if actual == *value);
                len += 1;
            }
            ConditionOp::AttrEqInt { key, value } => {
                stack[len] = matches!(context.get(key.as_atom()), Some(ValueRef::Int(actual)) if actual == *value);
                len += 1;
            }
            ConditionOp::AttrEqStr { key, value } => {
                stack[len] = matches!(context.get(key.as_atom()), Some(ValueRef::Str(actual)) if actual == value.as_atom());
                len += 1;
            }
            ConditionOp::True => {
                stack[len] = true;
                len += 1;
            }
            ConditionOp::False => {
                stack[len] = false;
                len += 1;
            }
            ConditionOp::Not => {
                if len < 1 {
                    return Err(Error::ConditionStackUnderflow { op_index: index });
                }
                stack[len - 1] = !stack[len - 1];
            }
            ConditionOp::And => {
                if len < 2 {
                    return Err(Error::ConditionStackUnderflow { op_index: index });
                }
                let rhs = stack[len - 1];
                let lhs = stack[len - 2];
                let dst = len - 2; // lhs slot becomes the result; rhs slot is popped
                len -= 1;
                stack[dst] = lhs && rhs;
            }
            ConditionOp::Or => {
                if len < 2 {
                    return Err(Error::ConditionStackUnderflow { op_index: index });
                }
                let rhs = stack[len - 1];
                let lhs = stack[len - 2];
                let dst = len - 2; // lhs slot becomes the result; rhs slot is popped
                len -= 1;
                stack[dst] = lhs || rhs;
            }
        }
    }

    if len != 1 {
        return Err(Error::ConditionDoesNotReduceToSingleValue { remaining: len });
    }

    Ok(stack[0])
}

fn validate_condition_ops(ops: &[ConditionOp]) -> Result<(), Error> {
    if ops.is_empty() {
        return Err(Error::EmptyCondition);
    }

    if ops.len() > MAX_CONDITION_OPS {
        return Err(Error::TooManyConditionOps {
            limit: MAX_CONDITION_OPS,
            actual: ops.len(),
        });
    }

    let mut depth_stack = [0usize; MAX_CONDITION_STACK];
    let mut stack_len = 0usize;

    for (index, op) in ops.iter().enumerate() {
        match op {
            ConditionOp::AttrPresent { .. }
            | ConditionOp::AttrEqBool { .. }
            | ConditionOp::AttrEqInt { .. }
            | ConditionOp::AttrEqStr { .. }
            | ConditionOp::True
            | ConditionOp::False => {
                if stack_len == MAX_CONDITION_STACK {
                    return Err(Error::ConditionStackOverflow {
                        limit: MAX_CONDITION_STACK,
                    });
                }
                depth_stack[stack_len] = 1;
                stack_len += 1;
            }
            ConditionOp::Not => {
                if stack_len < 1 {
                    return Err(Error::ConditionStackUnderflow { op_index: index });
                }
                let depth = depth_stack[stack_len - 1] + 1;
                if depth > MAX_CONDITION_DEPTH {
                    return Err(Error::ConditionDepthExceeded {
                        limit: MAX_CONDITION_DEPTH,
                        actual: depth,
                    });
                }
                depth_stack[stack_len - 1] = depth;
            }
            ConditionOp::And | ConditionOp::Or => {
                if stack_len < 2 {
                    return Err(Error::ConditionStackUnderflow { op_index: index });
                }
                let rhs = depth_stack[stack_len - 1];
                let lhs = depth_stack[stack_len - 2];
                let dst = stack_len - 2; // lhs slot becomes the combined depth; rhs slot is popped
                stack_len -= 1;
                let depth = lhs.max(rhs) + 1;
                if depth > MAX_CONDITION_DEPTH {
                    return Err(Error::ConditionDepthExceeded {
                        limit: MAX_CONDITION_DEPTH,
                        actual: depth,
                    });
                }
                depth_stack[dst] = depth;
            }
        }
    }

    if stack_len != 1 {
        return Err(Error::ConditionDoesNotReduceToSingleValue {
            remaining: stack_len,
        });
    }

    Ok(())
}

fn charge(budget: &mut u32, units: u32, budget_limit: u32) -> Result<(), Error> {
    if *budget < units {
        return Err(Error::EvaluationBudgetExceeded {
            limit: budget_limit,
        });
    }

    *budget -= units;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atom::{Action, AtomRef, Principal, Resource};
    use crate::context::{Context, ContextEntry, ValueRef};

    fn empty_context<'a>() -> Context<'a> {
        Context::new(&[]).unwrap()
    }

    #[test]
    fn deny_overrides_allow() {
        let allow = Rule::allow("allow_read")
            .unwrap()
            .action_exact("read")
            .unwrap()
            .build();

        let deny = Rule::deny("deny_secret")
            .unwrap()
            .action_exact("read")
            .unwrap()
            .resource_exact("doc:secret")
            .unwrap()
            .build();

        let policy = Policy::new(vec![allow, deny]).unwrap();

        let decision = policy
            .evaluate(
                Principal::new("user:alice").unwrap(),
                Action::new("read").unwrap(),
                Resource::new("doc:secret").unwrap(),
                empty_context(),
            )
            .unwrap();

        assert_eq!(decision, Decision::Deny);
    }

    #[test]
    fn condition_program_validates_depth() {
        let ops = vec![
            ConditionOp::always_true(),
            ConditionOp::not(),
            ConditionOp::not(),
            ConditionOp::not(),
            ConditionOp::not(),
            ConditionOp::not(),
            ConditionOp::not(),
            ConditionOp::not(),
            ConditionOp::not(),
        ];

        assert!(matches!(
            ConditionProgram::new(ops),
            Err(Error::ConditionDepthExceeded {
                limit: MAX_CONDITION_DEPTH,
                actual: 9
            })
        ));
    }

    #[test]
    fn report_returns_matching_allow_when_no_deny_matches() {
        let condition = ConditionProgram::new(vec![
            ConditionOp::attr_eq_str("tenant", "acme").unwrap(),
            ConditionOp::attr_eq_bool("mfa", true).unwrap(),
            ConditionOp::and(),
        ])
        .unwrap();

        let rule = Rule::allow("allow_invoice_read")
            .unwrap()
            .principal_exact("user:alice")
            .unwrap()
            .action_exact("read")
            .unwrap()
            .resource_exact("invoice:123")
            .unwrap()
            .condition(condition)
            .build();

        let policy = Policy::new(vec![rule]).unwrap();

        let entries = [
            ContextEntry::new(
                AtomRef::new("tenant").unwrap(),
                ValueRef::Str(AtomRef::new("acme").unwrap()),
            ),
            ContextEntry::new(AtomRef::new("mfa").unwrap(), ValueRef::Bool(true)),
        ];
        let context = Context::new(&entries).unwrap();

        let report = policy
            .evaluate_with_report(
                Principal::new("user:alice").unwrap(),
                Action::new("read").unwrap(),
                Resource::new("invoice:123").unwrap(),
                context,
            )
            .unwrap();

        assert_eq!(report.decision, Decision::Allow);
        assert_eq!(report.matched_rule_index, Some(0));
        assert_eq!(report.matched_rule_name, Some("allow_invoice_read"));
    }

    // Budget unit cost model:
    //   - each selector check (principal / action / resource) costs 1 unit
    //   - each condition op costs 1 unit
    //   - budget is a global counter shared across all rules in one evaluation pass

    #[test]
    fn budget_exhausted_during_second_rule_selector() {
        // Rule 1 has an exact principal that will not match "user:alice".
        // The principal selector is checked (1 unit) and fails → the rule is skipped.
        // Rule 2 is Any/Any/Any.
        // The principal selector is checked (1 unit) and matches.
        // The action selector is checked (1 unit) and matches.
        // The resource selector tries to charge 1 more unit but the budget is 0 → exhausted.
        //
        // Total units needed to reach exhaustion: 1 (rule 1) + 2 (rule 2) + 1 (fails) = 4.
        // Budget set to 3 to trigger exhaustion on rule 2's resource check.
        let miss = Rule::allow("miss_on_principal")
            .unwrap()
            .principal_exact("user:bob")
            .unwrap()
            .build();
        let catch_all = Rule::allow("allow_all").unwrap().build();
        let policy = Policy::with_budget(vec![miss, catch_all], 3).unwrap();

        let result = policy.evaluate(
            Principal::new("user:alice").unwrap(),
            Action::new("read").unwrap(),
            Resource::new("invoice:123").unwrap(),
            empty_context(),
        );

        assert!(matches!(
            result,
            Err(Error::EvaluationBudgetExceeded { limit: 3 })
        ));
    }

    #[test]
    fn budget_exhausted_inside_condition_after_selectors() {
        // One Any/Any/Any rule with a 3-op condition:
        //   always_true(), always_true(), and()
        // Selector checks: 3 units (budget goes from 4 to 1).
        // Condition op 1 (always_true): 1 unit (budget goes to 0).
        // Condition op 2 (always_true): tries to charge 1 unit from 0 → exhausted.
        //
        // Proves the budget accumulates across the selector phase and into condition evaluation.
        let condition = ConditionProgram::new(vec![
            ConditionOp::always_true(),
            ConditionOp::always_true(),
            ConditionOp::and(),
        ])
        .unwrap();
        let rule = Rule::allow("allow_with_condition")
            .unwrap()
            .condition(condition)
            .build();
        let policy = Policy::with_budget(vec![rule], 4).unwrap();

        let result = policy.evaluate(
            Principal::new("user:alice").unwrap(),
            Action::new("read").unwrap(),
            Resource::new("invoice:123").unwrap(),
            empty_context(),
        );

        assert!(matches!(
            result,
            Err(Error::EvaluationBudgetExceeded { limit: 4 })
        ));
    }
}
