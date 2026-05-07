use async_trait::async_trait;

use crate::errors::BridgeError;
use crate::ethereum::DepositSubmissionResult;
use crate::runtime::{BaseBlockBatch, ChainEvent, EventId, NockBlockEvent};
use crate::types::{DepositSubmission, Tip5Hash};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NockTipInfo {
    pub height: u64,
    pub tip_hash: String,
}

#[async_trait]
pub trait BaseContractPort: Send + Sync {
    async fn submit_deposit(
        &self,
        submission: DepositSubmission,
    ) -> Result<DepositSubmissionResult, BridgeError>;

    async fn get_last_deposit_nonce(&self) -> Result<u64, BridgeError>;

    async fn is_deposit_processed(&self, tx_id: &Tip5Hash) -> Result<bool, BridgeError>;
}

#[async_trait]
pub trait BaseSourcePort: Send + Sync {
    async fn chain_tip_height(&self) -> Result<u64, BridgeError>;

    async fn fetch_batch(&self, start: u64, end: u64) -> Result<BaseBlockBatch, BridgeError>;
}

#[async_trait]
pub trait NockSourcePort: Send {
    async fn tip_info(&mut self) -> Result<Option<NockTipInfo>, BridgeError>;

    async fn fetch_block_at_height(
        &mut self,
        height: u64,
    ) -> Result<Option<NockBlockEvent>, BridgeError>;
}

#[async_trait]
pub trait KernelStatePort: Send + Sync {
    async fn peek_base_hold(&self) -> Result<bool, BridgeError>;

    async fn peek_base_next_height(&self) -> Result<Option<u64>, BridgeError>;

    async fn peek_nock_next_height(&self) -> Result<Option<u64>, BridgeError>;

    async fn emit_chain_event(&self, event: ChainEvent) -> Result<EventId, BridgeError>;

    fn set_base_tip_hash(&self, tip_hash: String);
}
