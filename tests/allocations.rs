use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use gate1::{
    Action, AtomRef, ConditionOp, ConditionProgram, Context, ContextEntry, Decision, Policy,
    Principal, Resource, Rule, ValueRef,
};

struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
        System.alloc_zeroed(layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn assert_no_eval_allocations<F>(mut f: F)
where
    F: FnMut(),
{
    ALLOCATIONS.store(0, Ordering::SeqCst);
    f();
    let observed = ALLOCATIONS.load(Ordering::SeqCst);
    assert_eq!(observed, 0, "expected zero allocations during evaluation");
}

#[test]
fn allow_decision_path_is_zero_alloc() {
    let rule = Rule::allow("allow_read")
        .unwrap()
        .action_exact("read")
        .unwrap()
        .resource_exact("invoice:7")
        .unwrap()
        .build();
    let policy = Policy::new(vec![rule]).unwrap();
    let context = Context::new(&[]).unwrap();

    assert_no_eval_allocations(|| {
        for _ in 0..1_000 {
            let decision = policy
                .evaluate(
                    Principal::new("user:alice").unwrap(),
                    Action::new("read").unwrap(),
                    Resource::new("invoice:7").unwrap(),
                    context,
                )
                .unwrap();
            assert_eq!(decision, Decision::Allow);
        }
    });
}

#[test]
fn deny_decision_path_is_zero_alloc() {
    let rule = Rule::deny("deny_non_mfa")
        .unwrap()
        .action_exact("write")
        .unwrap()
        .condition(
            ConditionProgram::new(vec![
                ConditionOp::attr_eq_bool("mfa", false).unwrap(),
            ])
            .unwrap(),
        )
        .build();
    let policy = Policy::new(vec![rule]).unwrap();
    let entries = [ContextEntry::new(
        AtomRef::new("mfa").unwrap(),
        ValueRef::Bool(false),
    )];
    let context = Context::new(&entries).unwrap();

    assert_no_eval_allocations(|| {
        for _ in 0..1_000 {
            let decision = policy
                .evaluate(
                    Principal::new("user:alice").unwrap(),
                    Action::new("write").unwrap(),
                    Resource::new("cluster:prod").unwrap(),
                    context,
                )
                .unwrap();
            assert_eq!(decision, Decision::Deny);
        }
    });
}

#[test]
fn no_match_path_is_zero_alloc() {
    let policy = Policy::new(vec![
        Rule::allow("allow_delete")
            .unwrap()
            .action_exact("delete")
            .unwrap()
            .build(),
    ])
    .unwrap();
    let context = Context::new(&[]).unwrap();

    assert_no_eval_allocations(|| {
        for _ in 0..1_000 {
            let decision = policy
                .evaluate(
                    Principal::new("user:alice").unwrap(),
                    Action::new("read").unwrap(),
                    Resource::new("doc:9").unwrap(),
                    context,
                )
                .unwrap();
            assert_eq!(decision, Decision::NoMatch);
        }
    });
}

#[test]
fn condition_path_is_zero_alloc() {
    let policy = Policy::new(vec![
        Rule::allow("allow_billing_admin")
            .unwrap()
            .action_exact("approve")
            .unwrap()
            .resource_exact("billing:monthly-close")
            .unwrap()
            .condition(
                ConditionProgram::new(vec![
                    ConditionOp::attr_eq_str("tenant", "acme").unwrap(),
                    ConditionOp::attr_eq_bool("mfa", true).unwrap(),
                    ConditionOp::and(),
                ])
                .unwrap(),
            )
            .build(),
    ])
    .unwrap();

    let entries = [
        ContextEntry::new(
            AtomRef::new("tenant").unwrap(),
            ValueRef::Str(AtomRef::new("acme").unwrap()),
        ),
        ContextEntry::new(AtomRef::new("mfa").unwrap(), ValueRef::Bool(true)),
    ];
    let context = Context::new(&entries).unwrap();

    assert_no_eval_allocations(|| {
        for _ in 0..1_000 {
            let decision = policy
                .evaluate(
                    Principal::new("user:alice").unwrap(),
                    Action::new("approve").unwrap(),
                    Resource::new("billing:monthly-close").unwrap(),
                    context,
                )
                .unwrap();
            assert_eq!(decision, Decision::Allow);
        }
    });
}
