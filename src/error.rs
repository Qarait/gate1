use core::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    EmptyAtom,
    AtomTooLong {
        limit: usize,
        actual: usize,
    },
    InvalidAtomChar {
        index: usize,
        byte: u8,
    },
    TooManyContextEntries {
        limit: usize,
        actual: usize,
    },
    DuplicateContextKey {
        first: usize,
        second: usize,
    },
    EmptyCondition,
    TooManyConditionOps {
        limit: usize,
        actual: usize,
    },
    ConditionStackUnderflow {
        op_index: usize,
    },
    ConditionStackOverflow {
        limit: usize,
    },
    ConditionDepthExceeded {
        limit: usize,
        actual: usize,
    },
    ConditionDoesNotReduceToSingleValue {
        remaining: usize,
    },
    TooManyRules {
        limit: usize,
        actual: usize,
    },
    DuplicateRuleName {
        first: usize,
        second: usize,
    },
    ZeroEvaluationBudget,
    EvaluationBudgetExceeded {
        limit: u32,
    },
    EmptySelectorSet,
    SelectorSetTooLarge {
        limit: usize,
        actual: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAtom => write!(f, "atoms must not be empty"),
            Self::AtomTooLong { limit, actual } => {
                write!(f, "atom length {} exceeds limit {}", actual, limit)
            }
            Self::InvalidAtomChar { index, byte } => write!(
                f,
                "invalid atom byte 0x{byte:02x} at index {index}; only [a-z0-9._:/-] are allowed"
            ),
            Self::TooManyContextEntries { limit, actual } => {
                write!(f, "context entry count {} exceeds limit {}", actual, limit)
            }
            Self::DuplicateContextKey { first, second } => write!(
                f,
                "duplicate context key detected at entries {} and {}",
                first, second
            ),
            Self::EmptyCondition => write!(f, "condition program must not be empty"),
            Self::TooManyConditionOps { limit, actual } => {
                write!(f, "condition op count {} exceeds limit {}", actual, limit)
            }
            Self::ConditionStackUnderflow { op_index } => {
                write!(f, "condition stack underflow at op {}", op_index)
            }
            Self::ConditionStackOverflow { limit } => {
                write!(f, "condition stack exceeds limit {}", limit)
            }
            Self::ConditionDepthExceeded { limit, actual } => write!(
                f,
                "condition depth {} exceeds limit {}",
                actual, limit
            ),
            Self::ConditionDoesNotReduceToSingleValue { remaining } => write!(
                f,
                "condition program must reduce to one value; {} values remain",
                remaining
            ),
            Self::TooManyRules { limit, actual } => {
                write!(f, "rule count {} exceeds limit {}", actual, limit)
            }
            Self::DuplicateRuleName { first, second } => write!(
                f,
                "duplicate rule name detected at rules {} and {}",
                first, second
            ),
            Self::ZeroEvaluationBudget => write!(f, "evaluation budget must be greater than zero"),
            Self::EvaluationBudgetExceeded { limit } => {
                write!(f, "evaluation budget exhausted (limit {})", limit)
            }
            Self::EmptySelectorSet => write!(f, "selector set must not be empty"),
            Self::SelectorSetTooLarge { limit, actual } => {
                write!(f, "selector set size {} exceeds limit {}", actual, limit)
            }
        }
    }
}

impl std::error::Error for Error {}
