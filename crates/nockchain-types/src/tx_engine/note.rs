use std::collections::HashSet;

use anyhow::Result;
use ibig::{ubig, UBig};
use nockapp::Noun;
use nockchain_math::belt::{Belt, PRIME};
use nockchain_math::crypto::cheetah::{CheetahError, CheetahPoint};
use nockchain_math::noun_ext::NounMathExt;
use nockchain_math::structs::HoonMapIter;
use nockchain_math::zoon::common::DefaultTipHasher;
use nockchain_math::zoon::{zmap, zset};
use nockvm::noun::{NounAllocator, D, SIG};
use noun_serde::{NounDecode, NounDecodeError, NounEncode};
use serde::{Deserialize, Serialize};

// Nockchain Note
//
//   +$  form
//  $:  $:  version=%0  ::  utxo version number
//        ::    the page number in which the note was added to the balance.
//        ::NOTE while for dumbnet this could be block-id instead, and that
//        ::would simplify some code, for airwalk this would lead to a hashloop
//        origin-page=page-number
//        ::    a note with a null timelock has no page-number restrictions
//        ::    on when it may be spent
//        =timelock
//    ==
//  ::
//    name=Name
//    =lock
//    =source
//    assets=coins
//  ==
//
// #[derive(Clone, PartialEq, ::prost::Message)]
//pub struct WalletBalanceData {
//    /// note name -> amount
//    #[prost(message, repeated, tag = "1")]
//    pub notes: ::prost::alloc::vec::Vec<BalanceEntry>,
//    /// block height where balance was computed
//    #[prost(uint64, repeated, tag = "2")]
//    pub height: ::prost::alloc::vec::Vec<u64>,
//    /// block where balance was computed
//    #[prost(string, optional, tag = "3")]
//    pub block_id: ::core::option::Option<::prost::alloc::string::String>,
//}
//
#[derive(Debug, Clone, PartialEq, Eq, Hash, NounDecode, NounEncode)]
pub struct SchnorrPubkey(pub CheetahPoint);

impl SchnorrPubkey {
    pub fn to_base58(&self) -> Result<String, CheetahError> {
        Ok(CheetahPoint::into_base58(&self.0)?)
    }
    pub fn from_base58(b58: &str) -> Result<Self, CheetahError> {
        Ok(SchnorrPubkey(CheetahPoint::from_base58(b58)?))
    }
}

/// A transaction lock type
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lock {
    /// Number of required signatures to spend the note
    pub keys_required: u64,
    /// Set of public keys that can sign
    pub pubkeys: Vec<SchnorrPubkey>,
}

impl NounEncode for Lock {
    fn to_noun<A: NounAllocator>(&self, stack: &mut A) -> Noun {
        let m = u64::to_noun(&self.keys_required, stack);
        let keys_noun_map = self
            .pubkeys
            .iter()
            .fold(SIG, |map, pubkey: &SchnorrPubkey| {
                let mut val = pubkey.to_noun(stack);
                zset::z_set_put(stack, &map, &mut val, &DefaultTipHasher)
                    .expect("Failed to put public key into set")
            });
        let lock_noun = nockvm::noun::T(stack, &[m, keys_noun_map]);
        lock_noun
    }
}

impl NounDecode for Lock {
    fn from_noun(noun: &Noun) -> Result<Self, NounDecodeError> {
        let cell = noun.as_cell()?;
        let keys_required = cell.head().as_atom()?.as_u64()? as u64;

        // It is called HoonMapIter, but it can be used for sets as well
        let pubkeys_iter = HoonMapIter::from(cell.tail());

        let mut pubkeys = Vec::new();
        for pubkey in pubkeys_iter {
            let schnorr = SchnorrPubkey::from_noun(&pubkey)?;
            pubkeys.push(schnorr);
        }

        let unique = pubkeys.iter().collect::<HashSet<_>>();

        if pubkeys.len() != unique.len() {
            return Err(NounDecodeError::Custom(
                "Expected unique public keys".to_string(),
            ));
        }

        if keys_required == 0 {
            tracing::warn!("NounDecode Lock: expected m > 0");
        }

        if keys_required > unique.len() as u64 {
            tracing::warn!("NounDecode Lock: expected m <= number of public keys");
        }

        Ok(Lock {
            keys_required,
            pubkeys,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, NounEncode, NounDecode)]
pub struct Note {
    pub head: NoteHead,
    pub tail: NoteTail,
}

#[derive(Debug, Clone, PartialEq, Eq, NounEncode, NounDecode)]
pub struct NoteHead {
    pub version: Version,
    pub origin_page: BlockHeight,
    pub timelock: Timelock,
}

#[derive(Debug, Clone, PartialEq, Eq, NounEncode, NounDecode)]
pub struct NoteTail {
    pub name: Name,
    pub lock: Lock,
    pub source: Source,
    pub assets: Nicks,
}

#[derive(Debug, Clone, PartialEq, Eq, NounEncode, NounDecode)]
pub struct Nicks(pub usize);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Balance(pub Vec<(Name, Note)>);

impl NounEncode for Balance {
    fn to_noun<A: NounAllocator>(&self, stack: &mut A) -> Noun {
        let keys_noun_map = self.0.iter().fold(D(0), |map, (name, note)| {
            let mut key = name.to_noun(stack);
            let mut value = note.to_noun(stack);
            zmap::z_map_put(stack, &map, &mut key, &mut value, &DefaultTipHasher).unwrap()
        });
        keys_noun_map
    }
}

impl NounDecode for Balance {
    fn from_noun(noun: &Noun) -> Result<Self, NounDecodeError> {
        let notes = HoonMapIter::from(*noun)
            .filter(|kv| kv.is_cell())
            .map(|kv| {
                let [k, v] = kv.uncell()?;
                let name = Name::from_noun(&k)?;
                let note = Note::from_noun(&v)?;
                Ok((name, note))
            })
            .collect::<Result<Vec<_>, NounDecodeError>>()?;
        Ok(Balance(notes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, NounEncode, NounDecode, Serialize, Deserialize)]
pub struct BlockHeight(pub Belt);

#[derive(Debug, Clone, PartialEq, Eq, NounEncode, NounDecode, Serialize, Deserialize)]
pub struct BlockHeightDelta(pub Belt);

#[derive(Debug, Clone, PartialEq, Eq, NounDecode, NounEncode)]
pub struct BalanceUpdate {
    pub height: BlockHeight,
    pub block_id: Hash,
    pub notes: Balance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version {
    V0,
    V1,
    V2,
}

impl From<Version> for u32 {
    fn from(version: Version) -> Self {
        match version {
            Version::V0 => 0,
            Version::V1 => 1,
            Version::V2 => 2,
        }
    }
}

impl From<u32> for Version {
    fn from(version: u32) -> Self {
        match version {
            0 => Version::V0,
            1 => Version::V1,
            2 => Version::V2,
            _ => panic!("Invalid version"),
        }
    }
}

impl NounEncode for Version {
    fn to_noun<A: NounAllocator>(&self, _stack: &mut A) -> Noun {
        match self {
            Version::V0 => D(0),
            Version::V1 => D(1),
            Version::V2 => D(2),
        }
    }
}

impl NounDecode for Version {
    fn from_noun(noun: &Noun) -> Result<Self, NounDecodeError> {
        match noun.as_atom()?.as_direct() {
            Ok(ver) if ver.data() == 0 => Ok(Version::V0),
            Ok(ver) if ver.data() == 1 => Ok(Version::V1),
            Ok(ver) if ver.data() == 2 => Ok(Version::V2),
            _ => Err(NounDecodeError::InvalidEnumVariant),
        }
    }
}

// Tip5 hash representing the name of a note
#[derive(NounEncode, NounDecode, Clone, Debug, PartialEq, Eq)]
pub struct Name {
    /// First is the hash of whether the note has a timelock and the lock
    pub first: Hash,
    /// Last is the hash of the actual timelock and the source
    pub last: Hash,
    /// Signifies the ~ at the end of Name
    null: usize,
}

impl Name {
    pub fn new(first: Hash, last: Hash) -> Self {
        Self {
            first,
            last,
            null: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, NounEncode, NounDecode)]
pub struct Source {
    pub hash: Hash,
    pub is_coinbase: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, NounEncode, NounDecode)]
pub struct Timelock(pub Option<TimelockIntent>);

// Absolute range endpoints are absolute BlockHeight values
#[derive(Debug, Clone, PartialEq, Eq, NounEncode, NounDecode)]
pub struct TimelockRangeAbsolute {
    pub min: Option<BlockHeight>,
    pub max: Option<BlockHeight>,
}

impl TimelockRangeAbsolute {
    /// Creates new TimelockRangeAbsolute and normalizes the min and max.
    pub fn new(min: Option<BlockHeight>, max: Option<BlockHeight>) -> Self {
        // Turn Some(0) into None
        let min = min.filter(|height| (height.0).0 != 0);
        let max = max.filter(|height| (height.0).0 != 0);
        Self { min, max }
    }

    pub fn none() -> Self {
        Self {
            min: None,
            max: None,
        }
    }
}

// Relative range endpoints are deltas from the note's origin
#[derive(Debug, Clone, PartialEq, Eq, NounEncode, NounDecode)]
pub struct TimelockRangeRelative {
    pub min: Option<BlockHeightDelta>,
    pub max: Option<BlockHeightDelta>,
}

/// Creates new TimelockRangeRelative and normalizes the min and max.
impl TimelockRangeRelative {
    pub fn new(min: Option<BlockHeightDelta>, max: Option<BlockHeightDelta>) -> Self {
        // Turn Some(0) into None
        let min = min.filter(|height| (height.0).0 != 0);
        let max = max.filter(|height| (height.0).0 != 0);
        Self { min, max }
    }

    pub fn none() -> Self {
        Self {
            min: None,
            max: None,
        }
    }
}

/// Represents a timelock intent - optional constraint for output notes
#[derive(Debug, Clone, PartialEq, Eq, NounEncode, NounDecode)]
pub struct TimelockIntent {
    pub absolute: TimelockRangeAbsolute,
    pub relative: TimelockRangeRelative,
}

impl TimelockIntent {
    pub fn none() -> Self {
        Self {
            absolute: TimelockRangeAbsolute::none(),
            relative: TimelockRangeRelative::none(),
        }
    }
}

// A 5-cell of Belts
#[derive(Debug, Clone, PartialEq, Eq, Hash, NounDecode, NounEncode, Serialize, Deserialize)]
pub struct Hash(pub [Belt; 5]);

impl Hash {
    // TODO: use stackful UBig or different bigint crate
    // FIXME: This use of ibig's pow will leak memory.
    pub fn to_base58(&self) -> String {
        fn base_p_to_decimal<const N: usize>(belts: [Belt; N]) -> String {
            let prime_ubig = UBig::from(PRIME);
            let mut result = ubig!(0);

            for (i, value) in belts.iter().enumerate() {
                // Add the value * P^i to the result
                //accum_prime_ubig(&prime_ubig, &mut result, *value.into(), i);
                result += UBig::from(value.0) * prime_ubig.pow(i);
            }
            let bytes = result.to_be_bytes();
            bs58::encode(bytes).into_string()
        }
        base_p_to_decimal(self.0)
    }

    // TODO: test
    pub fn from_base58(s: &str) -> Result<Self, bs58::decode::Error> {
        let bytes = bs58::decode(s).into_vec()?;
        let mut value = UBig::from_be_bytes(&bytes);
        let mut belts = [Belt(0); 5];
        for i in 0..5 {
            belts[i] = Belt((value.clone() % PRIME) as u64);
            value /= PRIME;
        }
        Ok(Hash(belts))
    }

    pub fn to_array(&self) -> [u64; 5] {
        [self.0[0].0, self.0[1].0, self.0[2].0, self.0[3].0, self.0[4].0]
    }
}

#[cfg(test)]
mod test {
    use bytes::Bytes;
    use nockapp::noun::slab::NounSlab;
    use nockchain_math::belt::Belt;
    use nockvm::noun::NounAllocator;
    use noun_serde::{NounDecode, NounEncode};
    use quickcheck::{quickcheck, Arbitrary, Gen};

    use super::{
        Balance, BalanceUpdate, BlockHeight, BlockHeightDelta, Hash, Lock, Name, Nicks, Note,
        NoteHead, NoteTail, Source, Timelock, TimelockIntent, TimelockRangeAbsolute,
        TimelockRangeRelative, Version,
    };

    // TODO: implement a more elegant way of switching between cargo and bazel builds
    fn try_path(jam: &str) -> Result<Bytes, Box<dyn std::error::Error>> {
        let possible_paths = [
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("jams")
                .join(jam),
            std::path::Path::new("open/crates/nockchain-types/jams").join(jam),
        ];

        let jam_path = possible_paths
            .iter()
            .find_map(|path| std::fs::read(path).ok())
            .expect("Failed to read jam file from any known location");
        Ok(Bytes::from(jam_path))
    }

    #[test]
    fn test_balance() -> Result<(), Box<dyn std::error::Error>> {
        let balance_jam = try_path("balance.jam")?;
        let mut slab: NounSlab = NounSlab::new();
        let mut balance_noun = slab.cue_into(balance_jam)?;
        let balance = Balance::from_noun(&balance_noun)?;
        let mut balance_noun_from_struct = Balance::to_noun(&balance, &mut slab);
        unsafe { slab.equals(&mut balance_noun, &mut balance_noun_from_struct) };
        Ok(())
    }

    #[test]
    fn test_note() -> Result<(), Box<dyn std::error::Error>> {
        let note_jam = try_path("note.jam")?;
        let mut slab: NounSlab = NounSlab::new();
        let mut note_noun = slab.cue_into(note_jam)?;
        let note = Note::from_noun(&note_noun)?;
        let mut note_noun_from_struct = Note::to_noun(&note, &mut slab);
        assert!(unsafe { slab.equals(&mut note_noun, &mut note_noun_from_struct) });
        //eprintln!("{:?}", utxo);
        Ok(())
    }

    #[test]
    fn test_timelock() -> Result<(), Box<dyn std::error::Error>> {
        let timelock_jam = try_path("timelock.jam")?;
        let mut slab: NounSlab = NounSlab::new();
        let timelock_noun = slab.cue_into(timelock_jam)?;
        let _ = <Option<TimelockIntent>>::from_noun(&timelock_noun);
        Ok(())
    }

    fn bh(v: u64) -> BlockHeight {
        BlockHeight(Belt(v))
    }
    fn dh(v: u64) -> BlockHeightDelta {
        BlockHeightDelta(Belt(v))
    }

    #[test]
    fn test_timelock_roundtrip_none() {
        let mut slab: NounSlab = NounSlab::new();
        let tl = Timelock(None);
        let mut n1 = Timelock::to_noun(&tl, &mut slab);
        let tl2 = Timelock::from_noun(&n1).expect("decode");
        let mut n2 = Timelock::to_noun(&tl2, &mut slab);
        assert!(unsafe { slab.equals(&mut n1, &mut n2) });
    }

    #[test]
    fn test_timelock_roundtrip_absolute_only() {
        let mut slab: NounSlab = NounSlab::new();
        let tl = Timelock(Some(TimelockIntent {
            absolute: TimelockRangeAbsolute::new(Some(bh(100)), None),
            relative: TimelockRangeRelative::none(),
        }));
        let mut n1 = Timelock::to_noun(&tl, &mut slab);
        let tl2 = Timelock::from_noun(&n1).expect("decode");
        let mut n2 = Timelock::to_noun(&tl2, &mut slab);
        assert!(unsafe { slab.equals(&mut n1, &mut n2) });
    }

    #[test]
    fn hash_from_base58_accepts_valid_id() {
        let tx_id = "3giXkwW4zbFhoyJu27RbP6VNiYgR6yaTfk2AYnEHvxtVaGbmcVD6jb9";
        Hash::from_base58(tx_id).expect("expected valid base58 hash");
    }

    #[test]
    fn hash_from_base58_rejects_invalid_id() {
        let invalid_tx_id = "not-a-valid-hash";
        assert!(Hash::from_base58(invalid_tx_id).is_err());
    }

    #[test]
    fn hash_roundtrip_from_base58() {
        let tx_id = "3giXkwW4zbFhoyJu27RbP6VNiYgR6yaTfk2AYnEHvxtVaGbmcVD6jb9";
        let hash = Hash::from_base58(tx_id).expect("expected valid base58 hash");
        let hash_str = hash.to_base58();
        assert_eq!(hash_str, tx_id);
    }

    #[test]
    fn test_timelock_roundtrip_relative_only() {
        let mut slab: NounSlab = NounSlab::new();
        let tl = Timelock(Some(TimelockIntent {
            absolute: TimelockRangeAbsolute::none(),
            relative: TimelockRangeRelative::new(Some(dh(5)), Some(dh(50))),
        }));
        let mut n1 = Timelock::to_noun(&tl, &mut slab);
        let tl2 = Timelock::from_noun(&n1).expect("decode");
        let mut n2 = Timelock::to_noun(&tl2, &mut slab);
        assert!(unsafe { slab.equals(&mut n1, &mut n2) });
    }

    #[test]
    fn test_timelock_roundtrip_both() {
        let mut slab: NounSlab = NounSlab::new();
        let tl = Timelock(Some(TimelockIntent {
            absolute: TimelockRangeAbsolute::new(Some(bh(10)), Some(bh(20))),
            relative: TimelockRangeRelative::new(Some(dh(1)), Some(dh(2))),
        }));
        let mut n1 = Timelock::to_noun(&tl, &mut slab);
        let tl2 = Timelock::from_noun(&n1).expect("decode");
        let mut n2 = Timelock::to_noun(&tl2, &mut slab);
        assert!(unsafe { slab.equals(&mut n1, &mut n2) });
    }

    // ----------------------
    // QuickCheck generators
    // ----------------------
    fn arb_belt(g: &mut Gen) -> Belt {
        // Avoid extreme values that can trigger non-determinism in TIP hashing paths.
        let mut v = u64::arbitrary(g) & 0x7FFF_FFFF_FFFF_FFFF;
        if v == 0 {
            v = 1;
        }
        Belt(v)
    }
    fn arb_hash(g: &mut Gen) -> Hash {
        Hash([arb_belt(g), arb_belt(g), arb_belt(g), arb_belt(g), arb_belt(g)])
    }

    impl Arbitrary for Version {
        fn arbitrary(g: &mut Gen) -> Self {
            match u8::arbitrary(g) % 3 {
                0 => Version::V0,
                1 => Version::V1,
                _ => Version::V2,
            }
        }
    }

    impl Arbitrary for BlockHeight {
        fn arbitrary(g: &mut Gen) -> Self {
            BlockHeight(arb_belt(g))
        }
    }

    impl Arbitrary for BlockHeightDelta {
        fn arbitrary(g: &mut Gen) -> Self {
            BlockHeightDelta(arb_belt(g))
        }
    }

    impl Arbitrary for TimelockRangeAbsolute {
        fn arbitrary(g: &mut Gen) -> Self {
            let min = if bool::arbitrary(g) {
                Some(BlockHeight::arbitrary(g))
            } else {
                None
            };
            let max = if bool::arbitrary(g) {
                Some(BlockHeight::arbitrary(g))
            } else {
                None
            };
            TimelockRangeAbsolute { min, max }
        }
    }

    impl Arbitrary for TimelockRangeRelative {
        fn arbitrary(g: &mut Gen) -> Self {
            let min = if bool::arbitrary(g) {
                Some(BlockHeightDelta::arbitrary(g))
            } else {
                None
            };
            let max = if bool::arbitrary(g) {
                Some(BlockHeightDelta::arbitrary(g))
            } else {
                None
            };
            TimelockRangeRelative { min, max }
        }
    }

    impl Arbitrary for TimelockIntent {
        fn arbitrary(g: &mut Gen) -> Self {
            TimelockIntent {
                absolute: TimelockRangeAbsolute::arbitrary(g),
                relative: TimelockRangeRelative::arbitrary(g),
            }
        }
    }

    impl Arbitrary for Timelock {
        fn arbitrary(g: &mut Gen) -> Self {
            if bool::arbitrary(g) {
                Timelock(Some(TimelockIntent::arbitrary(g)))
            } else {
                Timelock(None)
            }
        }
    }

    impl Arbitrary for Name {
        fn arbitrary(g: &mut Gen) -> Self {
            Name {
                first: arb_hash(g),
                last: arb_hash(g),
                null: 0,
            }
        }
    }

    impl Arbitrary for Source {
        fn arbitrary(g: &mut Gen) -> Self {
            Source {
                hash: arb_hash(g),
                is_coinbase: bool::arbitrary(g),
            }
        }
    }

    impl Arbitrary for Lock {
        fn arbitrary(_g: &mut Gen) -> Self {
            Lock {
                keys_required: 0,
                pubkeys: Vec::new(),
            }
        }
    }

    impl Arbitrary for Nicks {
        fn arbitrary(g: &mut Gen) -> Self {
            Nicks((u16::arbitrary(g)) as usize)
        }
    }

    impl Arbitrary for NoteHead {
        fn arbitrary(g: &mut Gen) -> Self {
            NoteHead {
                version: Version::arbitrary(g),
                origin_page: BlockHeight::arbitrary(g),
                timelock: Timelock::arbitrary(g),
            }
        }
    }

    impl Arbitrary for NoteTail {
        fn arbitrary(g: &mut Gen) -> Self {
            NoteTail {
                name: Name::arbitrary(g),
                lock: Lock::arbitrary(g),
                source: Source::arbitrary(g),
                assets: Nicks::arbitrary(g),
            }
        }
    }

    impl Arbitrary for Note {
        fn arbitrary(g: &mut Gen) -> Self {
            Note {
                head: NoteHead::arbitrary(g),
                tail: NoteTail::arbitrary(g),
            }
        }
    }

    impl Arbitrary for Balance {
        fn arbitrary(g: &mut Gen) -> Self {
            use std::collections::HashSet;
            let mut set: HashSet<(Hash, Hash)> = HashSet::new();
            let mut items: Vec<(Name, Note)> = Vec::new();
            let len = 1 + (usize::arbitrary(g) % 5) as usize;
            for _ in 0..len {
                let name = Name::arbitrary(g);
                if set.insert((name.first.clone(), name.last.clone())) {
                    items.push((name, Note::arbitrary(g)));
                }
            }
            Balance(items)
        }
    }

    impl Arbitrary for BalanceUpdate {
        fn arbitrary(g: &mut Gen) -> Self {
            BalanceUpdate {
                height: BlockHeight::arbitrary(g),
                block_id: arb_hash(g),
                notes: Balance::arbitrary(g),
            }
        }
    }

    #[test]
    fn quickcheck_balance_update_noun_roundtrip() {
        fn prop(update: BalanceUpdate) -> bool {
            let mut slab: NounSlab = NounSlab::new();
            let mut n1 = BalanceUpdate::to_noun(&update, &mut slab);
            let decoded = match BalanceUpdate::from_noun(&n1) {
                Ok(v) => v,
                Err(_) => return false,
            };
            let mut n2 = BalanceUpdate::to_noun(&decoded, &mut slab);
            unsafe { slab.equals(&mut n1, &mut n2) }
        }
        quickcheck(prop as fn(BalanceUpdate) -> bool);
    }
}
