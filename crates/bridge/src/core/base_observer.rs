use crate::errors::BridgeError;
use crate::ports::{BaseSourcePort, KernelStatePort};
use crate::runtime::ChainEvent;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BaseObserverCore {
    pub batch_size: u64,
    pub confirmation_depth: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BasePlanInput {
    pub state: BasePlanState,
    pub batch_size: u64,
    pub confirmation_depth: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BasePlanState {
    HoldActive,
    Active {
        chain_tip: u64,
        next_needed_height: Option<u64>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BasePlanError {
    ZeroBatchSize,
    ZeroConfirmationDepth,
    HeightOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BasePlanAction {
    HoldActive,
    NoPendingHeight {
        chain_tip: u64,
    },
    InvalidConfig(BasePlanError),
    NotYetConfirmed {
        chain_tip: u64,
        confirmed_height: u64,
        next_needed_height: u64,
        needed_confirmed_height: u64,
        blocks_until_ready: u64,
    },
    FetchWindow {
        chain_tip: u64,
        confirmed_height: u64,
        start: u64,
        end: u64,
    },
}

pub fn plan_base_tick(input: BasePlanInput) -> BasePlanAction {
    if input.batch_size == 0 {
        return BasePlanAction::InvalidConfig(BasePlanError::ZeroBatchSize);
    }
    if input.confirmation_depth == 0 {
        return BasePlanAction::InvalidConfig(BasePlanError::ZeroConfirmationDepth);
    }

    let (chain_tip, next_needed_height) = match input.state {
        BasePlanState::HoldActive => return BasePlanAction::HoldActive,
        BasePlanState::Active {
            chain_tip,
            next_needed_height,
        } => (chain_tip, next_needed_height),
    };

    let Some(next_needed_height) = next_needed_height else {
        return BasePlanAction::NoPendingHeight { chain_tip };
    };

    let confirmed_height = chain_tip.saturating_sub(input.confirmation_depth);
    let Some(batch_end) = next_needed_height.checked_add(input.batch_size - 1) else {
        return BasePlanAction::InvalidConfig(BasePlanError::HeightOverflow);
    };

    if batch_end > confirmed_height {
        return BasePlanAction::NotYetConfirmed {
            chain_tip,
            confirmed_height,
            next_needed_height,
            needed_confirmed_height: batch_end,
            blocks_until_ready: batch_end.saturating_sub(confirmed_height),
        };
    }

    BasePlanAction::FetchWindow {
        chain_tip,
        confirmed_height,
        start: next_needed_height,
        end: batch_end,
    }
}

impl BaseObserverCore {
    pub fn plan_tick(&self, state: BasePlanState) -> BasePlanAction {
        plan_base_tick(BasePlanInput {
            state,
            batch_size: self.batch_size,
            confirmation_depth: self.confirmation_depth,
        })
    }
}

pub struct BaseObserverRunner<S, K> {
    pub core: BaseObserverCore,
    pub source: S,
    pub kernel: K,
}

impl<S, K> BaseObserverRunner<S, K>
where
    S: BaseSourcePort,
    K: KernelStatePort,
{
    pub async fn tick_once(&self) -> Result<BasePlanAction, BridgeError> {
        let state = if self.kernel.peek_base_hold().await? {
            BasePlanState::HoldActive
        } else {
            BasePlanState::Active {
                chain_tip: self.source.chain_tip_height().await?,
                next_needed_height: self.kernel.peek_base_next_height().await?,
            }
        };
        let action = self.core.plan_tick(state);

        if let BasePlanAction::FetchWindow { start, end, .. } = action {
            let batch = self.source.fetch_batch(start, end).await?;
            let _ = self
                .kernel
                .emit_chain_event(ChainEvent::Base(batch))
                .await?;
        }

        Ok(action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_pending_height_when_kernel_has_no_work() {
        let action = plan_base_tick(BasePlanInput {
            state: BasePlanState::Active {
                chain_tip: 100,
                next_needed_height: None,
            },
            batch_size: 100,
            confirmation_depth: 5,
        });
        assert_eq!(action, BasePlanAction::NoPendingHeight { chain_tip: 100 });
    }

    #[test]
    fn hold_active_short_circuits_planner() {
        let action = plan_base_tick(BasePlanInput {
            state: BasePlanState::HoldActive,
            batch_size: 100,
            confirmation_depth: 5,
        });
        assert_eq!(action, BasePlanAction::HoldActive);
    }

    #[test]
    fn invalid_when_batch_size_zero() {
        let action = plan_base_tick(BasePlanInput {
            state: BasePlanState::Active {
                chain_tip: 100,
                next_needed_height: Some(1),
            },
            batch_size: 0,
            confirmation_depth: 5,
        });
        assert_eq!(
            action,
            BasePlanAction::InvalidConfig(BasePlanError::ZeroBatchSize)
        );
    }

    #[test]
    fn not_yet_confirmed_for_next_window() {
        let action = plan_base_tick(BasePlanInput {
            state: BasePlanState::Active {
                chain_tip: 2800,
                next_needed_height: Some(2001),
            },
            batch_size: 1000,
            confirmation_depth: 300,
        });

        assert!(matches!(
            action,
            BasePlanAction::NotYetConfirmed {
                confirmed_height: 2500,
                next_needed_height: 2001,
                needed_confirmed_height: 3000,
                ..
            }
        ));
    }

    #[test]
    fn fetches_exact_confirmed_window() {
        let action = plan_base_tick(BasePlanInput {
            state: BasePlanState::Active {
                chain_tip: 2800,
                next_needed_height: Some(1001),
            },
            batch_size: 1000,
            confirmation_depth: 300,
        });

        assert_eq!(
            action,
            BasePlanAction::FetchWindow {
                chain_tip: 2800,
                confirmed_height: 2500,
                start: 1001,
                end: 2000,
            }
        );
    }

    #[test]
    fn detects_height_overflow() {
        let action = plan_base_tick(BasePlanInput {
            state: BasePlanState::Active {
                chain_tip: u64::MAX,
                next_needed_height: Some(u64::MAX),
            },
            batch_size: 2,
            confirmation_depth: 1,
        });

        assert_eq!(
            action,
            BasePlanAction::InvalidConfig(BasePlanError::HeightOverflow)
        );
    }
}
