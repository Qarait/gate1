use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use gate1::{
    Action, AtomRef, ConditionOp, ConditionProgram, Context, ContextEntry, Decision, Policy,
    Principal, Resource, Rule, ValueRef,
};

fn empty_context<'a>() -> Context<'a> {
    Context::new(&[]).unwrap()
}

// ── Fixture builders ────────────────────────────────────────────────────────

fn allow_path_policy() -> Policy {
    Policy::new(vec![Rule::allow("allow_read")
        .unwrap()
        .principal_exact("user:alice")
        .unwrap()
        .action_exact("read")
        .unwrap()
        .resource_exact("invoice:123")
        .unwrap()
        .build()])
    .unwrap()
}

fn no_match_policy() -> Policy {
    // Policy only allows "write"; benchmark sends "read" → NoMatch.
    Policy::new(vec![Rule::allow("allow_write")
        .unwrap()
        .action_exact("write")
        .unwrap()
        .build()])
    .unwrap()
}

fn prefix_policy() -> Policy {
    Policy::new(vec![Rule::allow("allow_billing_namespace")
        .unwrap()
        .resource_prefix("billing:")
        .unwrap()
        .build()])
    .unwrap()
}

fn set_policy() -> Policy {
    Policy::new(vec![Rule::allow("allow_rw_actions")
        .unwrap()
        .action_set(vec!["read", "write", "list"])
        .unwrap()
        .build()])
    .unwrap()
}

fn condition_policy() -> Policy {
    let condition = ConditionProgram::new(vec![
        ConditionOp::attr_eq_str("tenant", "acme").unwrap(),
        ConditionOp::attr_eq_bool("mfa", true).unwrap(),
        ConditionOp::and(),
    ])
    .unwrap();
    Policy::new(vec![Rule::allow("allow_mfa_acme")
        .unwrap()
        .condition(condition)
        .build()])
    .unwrap()
}

/// Worst-case: many rules, only the last one matches.
fn worst_case_policy(rule_count: usize) -> Policy {
    let mut rules: Vec<_> = (0..rule_count - 1)
        .map(|i| {
            Rule::allow(format!("miss-{i}"))
                .unwrap()
                .principal_exact(format!("user:ghost-{i}"))
                .unwrap()
                .build()
        })
        .collect();
    rules.push(
        Rule::allow("catch-all")
            .unwrap()
            .principal_exact("user:alice")
            .unwrap()
            .build(),
    );
    Policy::new(rules).unwrap()
}

// ── Benchmarks ───────────────────────────────────────────────────────────────

fn bench_allow_path(c: &mut Criterion) {
    let policy = allow_path_policy();
    let principal = Principal::new("user:alice").unwrap();
    let action = Action::new("read").unwrap();
    let resource = Resource::new("invoice:123").unwrap();

    c.bench_function("allow_path", |b| {
        b.iter(|| {
            let ctx = empty_context();
            policy
                .evaluate(
                    black_box(principal),
                    black_box(action),
                    black_box(resource),
                    black_box(ctx),
                )
                .unwrap()
        })
    });
}

fn bench_no_match_path(c: &mut Criterion) {
    let policy = no_match_policy();
    let principal = Principal::new("user:bob").unwrap();
    let action = Action::new("read").unwrap();
    let resource = Resource::new("doc:5").unwrap();

    c.bench_function("no_match_path", |b| {
        b.iter(|| {
            let ctx = empty_context();
            policy
                .evaluate(
                    black_box(principal),
                    black_box(action),
                    black_box(resource),
                    black_box(ctx),
                )
                .unwrap()
        })
    });
}

fn bench_prefix_selector(c: &mut Criterion) {
    let policy = prefix_policy();
    let principal = Principal::new("user:alice").unwrap();
    let action = Action::new("read").unwrap();
    let resource = Resource::new("billing:invoice-42").unwrap();

    c.bench_function("prefix_selector_match", |b| {
        b.iter(|| {
            let ctx = empty_context();
            let decision = policy
                .evaluate(
                    black_box(principal),
                    black_box(action),
                    black_box(resource),
                    black_box(ctx),
                )
                .unwrap();
            assert_eq!(decision, Decision::Allow);
        })
    });
}

fn bench_set_selector(c: &mut Criterion) {
    let policy = set_policy();
    let principal = Principal::new("user:alice").unwrap();
    let action = Action::new("write").unwrap();
    let resource = Resource::new("doc:report").unwrap();

    c.bench_function("set_selector_match", |b| {
        b.iter(|| {
            let ctx = empty_context();
            let decision = policy
                .evaluate(
                    black_box(principal),
                    black_box(action),
                    black_box(resource),
                    black_box(ctx),
                )
                .unwrap();
            assert_eq!(decision, Decision::Allow);
        })
    });
}

fn bench_condition_evaluation(c: &mut Criterion) {
    let policy = condition_policy();
    let principal = Principal::new("user:alice").unwrap();
    let action = Action::new("read").unwrap();
    let resource = Resource::new("doc:1").unwrap();
    let tenant_key = AtomRef::new("tenant").unwrap();
    let tenant_val = AtomRef::new("acme").unwrap();
    let mfa_key = AtomRef::new("mfa").unwrap();
    let entries = [
        ContextEntry::new(tenant_key, ValueRef::Str(tenant_val)),
        ContextEntry::new(mfa_key, ValueRef::Bool(true)),
    ];

    c.bench_function("condition_evaluation", |b| {
        b.iter(|| {
            let ctx = Context::new(black_box(&entries)).unwrap();
            let decision = policy
                .evaluate(
                    black_box(principal),
                    black_box(action),
                    black_box(resource),
                    black_box(ctx),
                )
                .unwrap();
            assert_eq!(decision, Decision::Allow);
        })
    });
}

fn bench_worst_case_rule_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("worst_case_rule_count");
    for count in [8, 16, 32, 64] {
        let policy = worst_case_policy(count);
        let principal = Principal::new("user:alice").unwrap();
        let action = Action::new("read").unwrap();
        let resource = Resource::new("doc:1").unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, _| {
            b.iter(|| {
                let ctx = empty_context();
                policy
                    .evaluate(
                        black_box(principal),
                        black_box(action),
                        black_box(resource),
                        black_box(ctx),
                    )
                    .unwrap()
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_allow_path,
    bench_no_match_path,
    bench_prefix_selector,
    bench_set_selector,
    bench_condition_evaluation,
    bench_worst_case_rule_count,
);
criterion_main!(benches);
