use std::error::Error;
use std::time::Duration;

use ibig::UBig;
use nockapp::noun::slab::Jammer;
use nockapp::noun::IntoSlab;
use nockapp::utils::make_tas;
use nockapp::wire::Wire;
use nockapp::{AtomExt, Bytes, NockApp, NockAppError, ToBytes};
use nockvm::noun::{Atom, D, NO, T, YES};
use nockvm_macros::tas;

use crate::NounSlab;

#[cfg(feature = "bazel_build")]
pub static FAKENET_GENESIS_BLOCK: &[u8] = include_bytes!(env!("FAKENET_GENESIS_PATH"));

#[cfg(not(feature = "bazel_build"))]
pub static FAKENET_GENESIS_BLOCK: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/jams/fakenet-genesis-pow-2-bex-1.jam"
));

// TODO: Necessary for now, but we will delete this parameter from genesis seal
pub const DEFAULT_GENESIS_BLOCK_HEIGHT: u64 = 0;
pub const FAKENET_GENESIS_MESSAGE: &str = "3WNP3WtcQJYtP5PCvFHDQVEeiZEznsULEY5Lc4vUKV64Ge8feBxAkYp";
pub const REALNET_GENESIS_MESSAGE: &str = "2c8Ltbg44dPkEGcNPupcVAtDgD87753M9pG2fg8yC2mTEqg5qAFvvbT";

pub enum SetupCommand {
    PokeFakenetConstants(BlockchainConstants),
    PokeSetGenesisSeal(String),
    PokeSetBtcData,
}

pub fn fakenet_blockchain_constaints(pow_len: u64, target_bex: u64) -> BlockchainConstants {
    BlockchainConstants::new()
        .with_pow_len(pow_len)
        .with_genesis_target_atom_bex(target_bex as u128)
        .with_update_candidate_timestamp_interval(Seconds(15 * 60))
        .with_coinbase_timelock_min(0)
        .with_first_month_coinbase_min(0)
}

pub async fn poke<J: Jammer + Send + 'static>(
    nockapp: &mut NockApp<J>,
    command: SetupCommand,
) -> Result<(), Box<dyn Error>> {
    let poke: NounSlab = match command {
        SetupCommand::PokeFakenetConstants(constants) => {
            let mut poke_slab = NounSlab::new();
            let tag = make_tas(&mut poke_slab, "set-constants").as_noun();

            let constants_slab = constants.into_slab();
            poke_slab.copy_from_slab(&constants_slab);
            poke_slab.modify(|constants| vec![D(tas!(b"command")), tag, constants]);
            poke_slab
        }
        SetupCommand::PokeSetGenesisSeal(seal) => {
            let mut poke_slab = NounSlab::new();
            let block_height_noun =
                Atom::new(&mut poke_slab, DEFAULT_GENESIS_BLOCK_HEIGHT).as_noun();
            let seal_byts = Bytes::from(
                seal.to_bytes()
                    .expect("Failed to convert seal message to bytes"),
            );
            let seal_noun = Atom::from_bytes(&mut poke_slab, &seal_byts).as_noun();
            let tag = Bytes::from(b"set-genesis-seal".to_vec());
            let set_genesis_seal = Atom::from_bytes(&mut poke_slab, &tag).as_noun();
            let poke_noun = T(
                &mut poke_slab,
                &[D(tas!(b"command")), set_genesis_seal, block_height_noun, seal_noun],
            );
            poke_slab.set_root(poke_noun);
            poke_slab
        }
        SetupCommand::PokeSetBtcData => {
            let mut poke_slab = NounSlab::new();
            let poke_noun = T(
                &mut poke_slab,
                &[D(tas!(b"command")), D(tas!(b"btc-data")), D(0)],
            );
            poke_slab.set_root(poke_noun);
            poke_slab
        }
    };

    nockapp
        .poke(nockapp::wire::SystemWire.to_wire(), poke)
        .await?;
    Ok(())
}

pub fn heard_fake_genesis_block(
    fake_genesis_data: Option<Vec<u8>>,
) -> Result<NounSlab, NockAppError> {
    let mut poke_slab = NounSlab::new();
    let tag = make_tas(&mut poke_slab, "heard-block").as_noun();
    // load the block bytes
    let block_bytes = if let Some(data) = fake_genesis_data {
        Bytes::from(data)
    } else {
        Bytes::from(FAKENET_GENESIS_BLOCK)
    };
    let block = poke_slab.cue_into(block_bytes)?;
    let poke_noun = T(&mut poke_slab, &[D(tas!(b"fact")), D(0), tag, block]);
    poke_slab.set_root(poke_noun);
    Ok(poke_slab)
}

const ATOMS_PER_SEC: u128 = 1 << 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Seconds(u64);

impl Seconds {
    pub fn new(seconds: u64) -> Self {
        Self(seconds)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn to_duration(&self) -> Duration {
        Duration::from_secs(self.0)
    }
}

impl From<u64> for Seconds {
    fn from(seconds: u64) -> Self {
        Self(seconds)
    }
}

impl TryFrom<Duration> for Seconds {
    type Error = &'static str;

    fn try_from(duration: Duration) -> Result<Self, Self::Error> {
        if duration.subsec_nanos() != 0 {
            return Err("Duration must be whole seconds only");
        }
        Ok(Self(duration.as_secs()))
    }
}

impl From<Seconds> for Duration {
    fn from(seconds: Seconds) -> Self {
        Duration::from_secs(seconds.0)
    }
}

pub struct BlockchainConstants {
    // In bits
    pub max_block_size: u64,
    pub blocks_per_epoch: u64,
    // In seconds
    pub target_epoch_duration: Seconds,
    // in seconds
    pub update_candidate_timestamp_interval: Seconds,
    // in seconds
    pub max_future_timestamp: Seconds,
    pub min_past_blocks: u64,
    pub genesis_target_atom: UBig,
    pub max_target_atom: UBig,
    pub check_pow_flag: bool,
    pub coinbase_timelock_min: u64,
    pub pow_len: u64,
    pub max_coinbase_split: u64,
    pub first_month_coinbase_min: u64,
}

impl BlockchainConstants {
    pub const DEFAULT_MAX_BLOCK_SIZE: u64 = 8000000;
    pub const DEFAULT_BLOCKS_PER_EPOCH: u64 = 2016;
    pub const DEFAULT_TARGET_EPOCH_DURATION: u64 = 1209600;
    pub const DEFAULT_UPDATE_CANDIDATE_TIMESTAMP_INTERVAL_SECS: u64 = 120;
    pub const DEFAULT_MAX_FUTURE_TIMESTAMP: u64 = 7200;
    // DEFAULT_GENESIS_TARGET_ATOM = MAX_TIP5_ATOM / (2 << 14)
    pub const DEFAULT_GENESIS_TARGET_ATOM: &str =
        "0x3ffffffec0000003bffffff88000000b3ffffff34000000b3ffffff880000003bffffffec0000";
    // Largest tip5 hash in base-p form
    pub const DEFAULT_MAX_TIP5_ATOM: &str =
        "0xfffffffb0000000effffffe20000002cffffffcd0000002cffffffe20000000efffffffb00000000";
    pub const DEFAULT_MIN_PAST_BLOCKS: u64 = 11;
    pub const DEFAULT_CHECK_POW_FLAG: bool = true;
    pub const DEFAULT_COINBASE_TIMELOCK_MIN: u64 = 100;
    pub const DEFAULT_POW_LEN: u64 = 64;
    pub const DEFAULT_MAX_COINBASE_SPLIT: u64 = 2;
    pub const DEFAULT_FIRST_MONTH_COINBASE_MIN: u64 = 4383;

    pub fn new() -> Self {
        let max_tip5_atom = UBig::from_str_with_radix_prefix(Self::DEFAULT_MAX_TIP5_ATOM)
            .expect("Failed to parse max tip5 atom");
        let genesis_target_atom =
            UBig::from_str_with_radix_prefix(Self::DEFAULT_GENESIS_TARGET_ATOM)
                .expect("Failed to parse genesis target atom");
        BlockchainConstants {
            max_block_size: Self::DEFAULT_MAX_BLOCK_SIZE,
            blocks_per_epoch: Self::DEFAULT_BLOCKS_PER_EPOCH,
            target_epoch_duration: Self::DEFAULT_TARGET_EPOCH_DURATION.into(),
            update_candidate_timestamp_interval:
                Self::DEFAULT_UPDATE_CANDIDATE_TIMESTAMP_INTERVAL_SECS.into(),
            max_future_timestamp: Self::DEFAULT_MAX_FUTURE_TIMESTAMP.into(),
            min_past_blocks: Self::DEFAULT_MIN_PAST_BLOCKS,
            genesis_target_atom: genesis_target_atom,
            max_target_atom: max_tip5_atom,
            check_pow_flag: Self::DEFAULT_CHECK_POW_FLAG,
            coinbase_timelock_min: Self::DEFAULT_COINBASE_TIMELOCK_MIN,
            pow_len: Self::DEFAULT_POW_LEN,
            max_coinbase_split: Self::DEFAULT_MAX_COINBASE_SPLIT,
            first_month_coinbase_min: Self::DEFAULT_FIRST_MONTH_COINBASE_MIN,
        }
    }

    pub fn with_genesis_target_atom_bex(mut self, bex: u128) -> Self {
        let difficulty = UBig::from((1 << bex) as u128);
        self.genesis_target_atom = self.max_target_atom.clone() / difficulty;
        eprintln!("Genesis target atom set to {}", self.genesis_target_atom);
        self
    }

    pub fn with_update_candidate_timestamp_interval(mut self, interval_secs: Seconds) -> Self {
        self.update_candidate_timestamp_interval = interval_secs;
        self
    }

    pub fn with_pow_len(mut self, pow_len: u64) -> Self {
        self.pow_len = pow_len;
        self
    }

    pub fn with_first_month_coinbase_min(mut self, coinbase_min: u64) -> Self {
        self.first_month_coinbase_min = coinbase_min;
        self
    }

    pub fn with_coinbase_timelock_min(mut self, coinbase_max: u64) -> Self {
        self.coinbase_timelock_min = coinbase_max;
        self
    }
}

impl IntoSlab for BlockchainConstants {
    fn into_slab(self) -> NounSlab {
        let mut slab = NounSlab::new();
        let max_block_size = Atom::new(&mut slab, self.max_block_size).as_noun();
        let blocks_per_epoch = Atom::new(&mut slab, self.blocks_per_epoch).as_noun();
        let target_epoch_duration = Atom::new(&mut slab, self.target_epoch_duration.0).as_noun();
        let update_candidate_timestamp_interval =
            UBig::from(self.update_candidate_timestamp_interval.0 as u128 * ATOMS_PER_SEC);
        let update_candidate_timestamp_interval =
            Atom::from_ubig(&mut slab, &update_candidate_timestamp_interval).as_noun();
        let max_future_timestamp = Atom::new(&mut slab, self.max_future_timestamp.0).as_noun();
        let min_past_blocks = Atom::new(&mut slab, self.min_past_blocks).as_noun();
        let genesis_target_atom = Atom::from_ubig(&mut slab, &self.genesis_target_atom).as_noun();
        let max_target_atom = Atom::from_ubig(&mut slab, &self.max_target_atom).as_noun();
        let check_pow_flag = if self.check_pow_flag { YES } else { NO };
        let coinbase_timelock_min = Atom::new(&mut slab, self.coinbase_timelock_min).as_noun();
        let pow_len = Atom::new(&mut slab, self.pow_len).as_noun();
        let max_coinbase_split = Atom::new(&mut slab, self.max_coinbase_split).as_noun();
        let first_month_coinbase_min =
            Atom::new(&mut slab, self.first_month_coinbase_min).as_noun();

        let constants = T(
            &mut slab,
            &[
                max_block_size, blocks_per_epoch, target_epoch_duration,
                update_candidate_timestamp_interval, max_future_timestamp, min_past_blocks,
                genesis_target_atom, max_target_atom, check_pow_flag, coinbase_timelock_min,
                pow_len, max_coinbase_split, first_month_coinbase_min,
            ],
        );
        slab.set_root(constants);
        slab
    }
}
