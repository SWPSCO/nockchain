use anyhow::Result;
use nockchain_math::belt::Belt as DBelt;
use nockchain_math::crypto::cheetah::{CheetahPoint as DCheetahPoint, F6lt as DF6lt};
use nockchain_types as domain;

use crate::pb::common::v1::{
    time_lock_intent, BalanceEntry, Belt, BlockHeight, BlockHeightDelta, CheetahPoint, EightBelt,
    ErrorStatus, Hash, Input as PbInput, Lock, Name, NamedInput as PbNamedInput, Nicks, Note,
    NoteVersion, OutputSource, RawTransaction as PbRawTransaction, SchnorrPubkey,
    SchnorrSignature as PbSchnorrSignature, Seed as PbSeed, Signature as PbSignature,
    SignatureEntry as PbSignatureEntry, Source, Spend as PbSpend, TimeLockIntent,
    TimeLockRangeAbsolute, TimeLockRangeAbsoluteAndRelative, TimeLockRangeNeither,
    TimeLockRangeRelative, WalletBalanceData,
};
use crate::pb::public::v1::{wallet_get_balance_response, WalletGetBalanceResponse};

pub trait Required<T> {
    fn required(self, kind: &'static str, field: &'static str) -> Result<T, ConversionError>;
}

impl<T> Required<T> for Option<T> {
    fn required(self, kind: &'static str, field: &'static str) -> Result<T, ConversionError> {
        self.ok_or_else(|| ConversionError::MissingField(kind, field))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("grpc error code={code}: {message} ({details:?})")]
pub struct RPCErrorStatus {
    pub code: i32,
    pub message: String,
    pub details: Option<String>,
}

impl From<ErrorStatus> for RPCErrorStatus {
    fn from(status: ErrorStatus) -> Self {
        RPCErrorStatus {
            code: status.code,
            message: status.message,
            details: status.details,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("cheetah error: {0}")]
    Cheetah(#[from] nockchain_math::crypto::cheetah::CheetahError),
    #[error("{0} is missing field: {1}")]
    MissingField(&'static str, &'static str),
    #[error("Invalid value: {0}")]
    Invalid(&'static str),
}
// =========================
// Helper: wrapper conversions (pb <-> domain)
// =========================

impl From<DBelt> for Belt {
    fn from(b: DBelt) -> Self {
        Belt { value: b.0 }
    }
}

impl From<Belt> for DBelt {
    fn from(b: Belt) -> Self {
        DBelt(b.value)
    }
}

impl From<[DBelt; 8]> for EightBelt {
    fn from(belts: [DBelt; 8]) -> Self {
        EightBelt {
            belt_1: Some(Belt::from(belts[0])),
            belt_2: Some(Belt::from(belts[1])),
            belt_3: Some(Belt::from(belts[2])),
            belt_4: Some(Belt::from(belts[3])),
            belt_5: Some(Belt::from(belts[4])),
            belt_6: Some(Belt::from(belts[5])),
            belt_7: Some(Belt::from(belts[6])),
            belt_8: Some(Belt::from(belts[7])),
        }
    }
}

impl TryFrom<EightBelt> for [DBelt; 8] {
    type Error = ConversionError;

    fn try_from(value: EightBelt) -> Result<Self, Self::Error> {
        Ok([
            value.belt_1.required("EightBelt", "belt_1")?.into(),
            value.belt_2.required("EightBelt", "belt_2")?.into(),
            value.belt_3.required("EightBelt", "belt_3")?.into(),
            value.belt_4.required("EightBelt", "belt_4")?.into(),
            value.belt_5.required("EightBelt", "belt_5")?.into(),
            value.belt_6.required("EightBelt", "belt_6")?.into(),
            value.belt_7.required("EightBelt", "belt_7")?.into(),
            value.belt_8.required("EightBelt", "belt_8")?.into(),
        ])
    }
}

impl From<DF6lt> for crate::pb::common::v1::SixBelt {
    fn from(f: DF6lt) -> Self {
        crate::pb::common::v1::SixBelt {
            belt_1: Some(Belt::from(f.0[0])),
            belt_2: Some(Belt::from(f.0[1])),
            belt_3: Some(Belt::from(f.0[2])),
            belt_4: Some(Belt::from(f.0[3])),
            belt_5: Some(Belt::from(f.0[4])),
            belt_6: Some(Belt::from(f.0[5])),
        }
    }
}

impl TryFrom<crate::pb::common::v1::SixBelt> for DF6lt {
    type Error = ConversionError;
    fn try_from(v: crate::pb::common::v1::SixBelt) -> Result<Self, Self::Error> {
        Ok(DF6lt([
            v.belt_1.required("SixBelt", "belt_1")?.into(),
            v.belt_2.required("SixBelt", "belt_2")?.into(),
            v.belt_3.required("SixBelt", "belt_3")?.into(),
            v.belt_4.required("SixBelt", "belt_4")?.into(),
            v.belt_5.required("SixBelt", "belt_5")?.into(),
            v.belt_6.required("SixBelt", "belt_6")?.into(),
        ]))
    }
}

impl From<DCheetahPoint> for CheetahPoint {
    fn from(p: DCheetahPoint) -> Self {
        CheetahPoint {
            x: Some(crate::pb::common::v1::SixBelt::from(p.x)),
            y: Some(crate::pb::common::v1::SixBelt::from(p.y)),
            inf: p.inf,
        }
    }
}

impl TryFrom<CheetahPoint> for DCheetahPoint {
    type Error = ConversionError;
    fn try_from(p: CheetahPoint) -> Result<Self, Self::Error> {
        Ok(DCheetahPoint {
            x: DF6lt::try_from(p.x.required("CheetahPoint", "x")?)?,
            y: DF6lt::try_from(p.y.required("CheetahPoint", "y")?)?,
            inf: p.inf,
        })
    }
}

impl From<domain::SchnorrPubkey> for SchnorrPubkey {
    fn from(pk: domain::SchnorrPubkey) -> Self {
        SchnorrPubkey {
            value: Some(CheetahPoint::from(pk.0)),
        }
    }
}

impl TryFrom<SchnorrPubkey> for domain::SchnorrPubkey {
    type Error = ConversionError;
    fn try_from(pk: SchnorrPubkey) -> Result<Self, Self::Error> {
        Ok(domain::SchnorrPubkey(DCheetahPoint::try_from(
            pk.value.required("SchnorrPubkey", "value")?,
        )?))
    }
}

impl From<domain::SchnorrSignature> for PbSchnorrSignature {
    fn from(sig: domain::SchnorrSignature) -> Self {
        PbSchnorrSignature {
            chal: Some(EightBelt::from(sig.chal)),
            sig: Some(EightBelt::from(sig.sig)),
        }
    }
}

impl TryFrom<PbSchnorrSignature> for domain::SchnorrSignature {
    type Error = ConversionError;

    fn try_from(sig: PbSchnorrSignature) -> Result<Self, Self::Error> {
        let chal = sig.chal.required("SchnorrSignature", "chal")?.try_into()?;
        let sig_val = sig.sig.required("SchnorrSignature", "sig")?.try_into()?;
        Ok(domain::SchnorrSignature { chal, sig: sig_val })
    }
}

impl From<domain::Signature> for PbSignature {
    fn from(signature: domain::Signature) -> Self {
        let entries = signature
            .0
            .into_iter()
            .map(|(pk, sig)| PbSignatureEntry {
                schnorr_pubkey: Some(SchnorrPubkey::from(pk)),
                signature: Some(PbSchnorrSignature::from(sig)),
            })
            .collect();
        PbSignature { entries }
    }
}

impl TryFrom<PbSignature> for domain::Signature {
    type Error = ConversionError;

    fn try_from(signature: PbSignature) -> Result<Self, Self::Error> {
        let mut entries = Vec::with_capacity(signature.entries.len());
        for entry in signature.entries {
            let pk: domain::SchnorrPubkey = entry
                .schnorr_pubkey
                .required("SignatureEntry", "schnorr_pubkey")?
                .try_into()?;
            let sig: domain::SchnorrSignature = entry
                .signature
                .required("SignatureEntry", "signature")?
                .try_into()?;
            entries.push((pk, sig));
        }
        Ok(domain::Signature(entries))
    }
}

impl From<domain::Spend> for PbSpend {
    fn from(spend: domain::Spend) -> Self {
        PbSpend {
            signature: spend.signature.map(PbSignature::from),
            seeds: spend.seeds.seeds.into_iter().map(PbSeed::from).collect(),
            miner_fee_nicks: Some(Nicks::from(spend.fee)),
        }
    }
}

impl TryFrom<PbSpend> for domain::Spend {
    type Error = ConversionError;

    fn try_from(spend: PbSpend) -> Result<Self, Self::Error> {
        let signature = spend.signature.map(TryInto::try_into).transpose()?;
        let seeds = spend
            .seeds
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()?;
        let seeds = domain::Seeds { seeds };
        let fee: domain::Nicks = spend
            .miner_fee_nicks
            .required("Spend", "miner_fee_nicks")?
            .into();
        Ok(domain::Spend {
            signature,
            seeds,
            fee,
        })
    }
}

impl From<domain::Hash> for Hash {
    fn from(h: domain::Hash) -> Self {
        Hash {
            belt_1: Some(Belt::from(h.0[0])),
            belt_2: Some(Belt::from(h.0[1])),
            belt_3: Some(Belt::from(h.0[2])),
            belt_4: Some(Belt::from(h.0[3])),
            belt_5: Some(Belt::from(h.0[4])),
        }
    }
}

impl TryFrom<Hash> for domain::Hash {
    type Error = ConversionError;
    fn try_from(h: Hash) -> Result<Self, Self::Error> {
        Ok(domain::Hash([
            h.belt_1.required("Hash", "belt_1")?.into(),
            h.belt_2.required("Hash", "belt_2")?.into(),
            h.belt_3.required("Hash", "belt_3")?.into(),
            h.belt_4.required("Hash", "belt_4")?.into(),
            h.belt_5.required("Hash", "belt_5")?.into(),
        ]))
    }
}

impl From<domain::Name> for Name {
    fn from(name: domain::Name) -> Self {
        Name {
            first: Some(Hash::from(name.first)),
            last: Some(Hash::from(name.last)),
        }
    }
}

impl TryFrom<Name> for domain::Name {
    type Error = ConversionError;
    fn try_from(name: Name) -> Result<Self, Self::Error> {
        let first: domain::Hash = name.first.required("Name", "first")?.try_into()?;
        let last: domain::Hash = name.last.required("Name", "last")?.try_into()?;
        Ok(domain::Name::new(first, last))
    }
}

impl From<domain::Lock> for Lock {
    fn from(lock: domain::Lock) -> Self {
        Lock {
            keys_required: lock.keys_required as u32,
            schnorr_pubkeys: lock.pubkeys.into_iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<Lock> for domain::Lock {
    type Error = ConversionError;
    fn try_from(lock: Lock) -> Result<Self, Self::Error> {
        Ok(domain::Lock {
            keys_required: lock.keys_required as u64,
            pubkeys: lock
                .schnorr_pubkeys
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl From<domain::Source> for Source {
    fn from(source: domain::Source) -> Self {
        Source {
            hash: Some(Hash::from(source.hash)),
            coinbase: source.is_coinbase,
        }
    }
}

impl TryFrom<Source> for domain::Source {
    type Error = ConversionError;
    fn try_from(source: Source) -> Result<Self, Self::Error> {
        Ok(domain::Source {
            hash: source.hash.required("Source", "hash")?.try_into()?,
            is_coinbase: source.coinbase,
        })
    }
}

impl From<domain::Seed> for PbSeed {
    fn from(seed: domain::Seed) -> Self {
        PbSeed {
            output_source: seed.output_source.map(|source| OutputSource {
                source: Some(Source::from(source)),
            }),
            recipient: Some(Lock::from(seed.recipient)),
            timelock_intent: seed
                .timelock_intent
                .map(|intent| TimeLockIntent::from(domain::Timelock(Some(intent)))),
            gift: Some(Nicks::from(seed.gift)),
            parent_hash: Some(Hash::from(seed.parent_hash)),
        }
    }
}

impl TryFrom<PbSeed> for domain::Seed {
    type Error = ConversionError;

    fn try_from(seed: PbSeed) -> Result<Self, Self::Error> {
        let output_source = match seed.output_source {
            Some(output) => {
                let source = output
                    .source
                    .required("Seed", "output_source.source")?
                    .try_into()?;
                Some(source)
            }
            None => None,
        };

        let recipient: domain::Lock = seed.recipient.required("Seed", "recipient")?.try_into()?;

        let timelock_intent = seed
            .timelock_intent
            .map(
                |intent| -> Result<Option<domain::TimelockIntent>, ConversionError> {
                    let timelock: domain::Timelock = intent.try_into()?;
                    Ok(timelock.0)
                },
            )
            .transpose()?
            .flatten();

        let gift: domain::Nicks = seed.gift.required("Seed", "gift")?.into();

        let parent_hash: domain::Hash = seed
            .parent_hash
            .required("Seed", "parent_hash")?
            .try_into()?;

        Ok(domain::Seed {
            output_source,
            recipient,
            timelock_intent,
            gift,
            parent_hash,
        })
    }
}

impl From<domain::Input> for PbInput {
    fn from(input: domain::Input) -> Self {
        PbInput {
            note: Some(Note::from(input.note)),
            spend: Some(PbSpend::from(input.spend)),
        }
    }
}

impl TryFrom<PbInput> for domain::Input {
    type Error = ConversionError;

    fn try_from(input: PbInput) -> Result<Self, Self::Error> {
        Ok(domain::Input {
            note: input.note.required("Input", "note")?.try_into()?,
            spend: input.spend.required("Input", "spend")?.try_into()?,
        })
    }
}

impl From<(domain::Name, domain::Input)> for PbNamedInput {
    fn from((name, input): (domain::Name, domain::Input)) -> Self {
        PbNamedInput {
            name: Some(Name::from(name)),
            input: Some(PbInput::from(input)),
        }
    }
}

impl TryFrom<PbNamedInput> for (domain::Name, domain::Input) {
    type Error = ConversionError;

    fn try_from(named: PbNamedInput) -> Result<Self, Self::Error> {
        let name = named.name.required("NamedInput", "name")?.try_into()?;
        let input = named.input.required("NamedInput", "input")?.try_into()?;
        Ok((name, input))
    }
}

impl From<domain::RawTx> for PbRawTransaction {
    fn from(tx: domain::RawTx) -> Self {
        PbRawTransaction {
            named_inputs: tx.inputs.0.into_iter().map(PbNamedInput::from).collect(),
            timelock_range: Some(TimeLockRangeAbsolute::from(tx.timelock_range)),
            total_fees: Some(Nicks::from(tx.total_fees)),
            id: Some(Hash::from(tx.id)),
        }
    }
}

impl TryFrom<PbRawTransaction> for domain::RawTx {
    type Error = ConversionError;

    fn try_from(tx: PbRawTransaction) -> Result<Self, Self::Error> {
        let inputs_vec = tx
            .named_inputs
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()?;
        let inputs = domain::Inputs(inputs_vec);
        let timelock_range: domain::TimelockRangeAbsolute = tx
            .timelock_range
            .required("RawTransaction", "timelock_range")?
            .into();
        let total_fees: domain::Nicks = tx
            .total_fees
            .required("RawTransaction", "total_fees")?
            .into();
        let id: domain::Hash = tx.id.required("RawTransaction", "id")?.try_into()?;

        Ok(domain::RawTx {
            id,
            inputs,
            timelock_range,
            total_fees,
        })
    }
}

impl From<domain::BlockHeight> for BlockHeight {
    fn from(h: domain::BlockHeight) -> Self {
        BlockHeight { value: (h.0).0 }
    }
}

impl From<BlockHeight> for domain::BlockHeight {
    fn from(h: BlockHeight) -> Self {
        domain::BlockHeight(DBelt(h.value))
    }
}

impl From<BlockHeightDelta> for domain::BlockHeightDelta {
    fn from(h: BlockHeightDelta) -> Self {
        domain::BlockHeightDelta(DBelt(h.value))
    }
}

impl From<domain::Nicks> for Nicks {
    fn from(n: domain::Nicks) -> Self {
        Nicks { value: n.0 as u64 }
    }
}

impl From<domain::BlockHeightDelta> for BlockHeightDelta {
    fn from(d: domain::BlockHeightDelta) -> Self {
        BlockHeightDelta { value: d.0 .0 }
    }
}

impl From<Nicks> for domain::Nicks {
    fn from(n: Nicks) -> Self {
        domain::Nicks(n.value as usize)
    }
}

impl From<domain::Version> for NoteVersion {
    fn from(v: domain::Version) -> Self {
        NoteVersion { value: v.into() }
    }
}

impl From<NoteVersion> for domain::Version {
    fn from(v: NoteVersion) -> Self {
        domain::Version::from(v.value)
    }
}

impl From<domain::TimelockRangeAbsolute> for TimeLockRangeAbsolute {
    fn from(range: domain::TimelockRangeAbsolute) -> Self {
        TimeLockRangeAbsolute {
            min: range.min.map(Into::into),
            max: range.max.map(Into::into),
        }
    }
}

impl From<TimeLockRangeAbsolute> for domain::TimelockRangeAbsolute {
    fn from(range: TimeLockRangeAbsolute) -> Self {
        domain::TimelockRangeAbsolute::new(
            range.min.map(|v| v.try_into().unwrap()),
            range.max.map(|v| v.try_into().unwrap()),
        )
    }
}

impl From<domain::TimelockRangeRelative> for TimeLockRangeRelative {
    fn from(range: domain::TimelockRangeRelative) -> Self {
        TimeLockRangeRelative {
            min: range.min.map(Into::into),
            max: range.max.map(Into::into),
        }
    }
}

impl From<TimeLockRangeRelative> for domain::TimelockRangeRelative {
    fn from(range: TimeLockRangeRelative) -> Self {
        domain::TimelockRangeRelative::new(
            range.min.map(|v| v.try_into().unwrap()),
            range.max.map(|v| v.try_into().unwrap()),
        )
    }
}

// Local helpers: None if both ends are None, otherwise Some(mapped range)
fn abs_range_to_opt(range: domain::TimelockRangeAbsolute) -> Option<TimeLockRangeAbsolute> {
    if range.min.is_none() && range.max.is_none() {
        None
    } else {
        Some(TimeLockRangeAbsolute::from(range))
    }
}

fn rel_range_to_opt(range: domain::TimelockRangeRelative) -> Option<TimeLockRangeRelative> {
    if range.min.is_none() && range.max.is_none() {
        None
    } else {
        Some(TimeLockRangeRelative::from(range))
    }
}

impl From<domain::Timelock> for TimeLockIntent {
    fn from(tl: domain::Timelock) -> Self {
        let value = match tl.0 {
            None => None,
            Some(intent) => {
                let abs = abs_range_to_opt(intent.absolute);
                let rel = rel_range_to_opt(intent.relative);
                match (abs, rel) {
                    (None, None) => Some(time_lock_intent::Value::Neither(TimeLockRangeNeither {})),
                    (Some(a), None) => Some(time_lock_intent::Value::Absolute(a)),
                    (None, Some(r)) => Some(time_lock_intent::Value::Relative(r)),
                    (Some(a), Some(r)) => Some(time_lock_intent::Value::AbsoluteAndRelative(
                        TimeLockRangeAbsoluteAndRelative {
                            absolute: Some(a),
                            relative: Some(r),
                        },
                    )),
                }
            }
        };
        TimeLockIntent { value }
    }
}

impl TryFrom<TimeLockIntent> for domain::Timelock {
    type Error = ConversionError;
    fn try_from(intent: TimeLockIntent) -> Result<Self, Self::Error> {
        let tl = match intent.value {
            Some(time_lock_intent::Value::Absolute(abs)) => {
                domain::Timelock(Some(domain::TimelockIntent {
                    absolute: abs.into(),
                    relative: domain::TimelockRangeRelative::none(),
                }))
            }
            Some(time_lock_intent::Value::Relative(rel)) => {
                domain::Timelock(Some(domain::TimelockIntent {
                    absolute: domain::TimelockRangeAbsolute::none(),
                    relative: rel.into(),
                }))
            }
            Some(time_lock_intent::Value::AbsoluteAndRelative(both)) => {
                let abs = both.absolute.ok_or(ConversionError::Invalid(
                    "absolute not present in AbsoluteAndRelative",
                ))?;
                let rel = both.relative.ok_or(ConversionError::Invalid(
                    "relative not present in AbsoluteAndRelative",
                ))?;
                domain::Timelock(Some(domain::TimelockIntent {
                    absolute: abs.into(),
                    relative: rel.into(),
                }))
            }
            Some(time_lock_intent::Value::Neither(..)) => {
                domain::Timelock(Some(domain::TimelockIntent::none()))
            }
            None => domain::Timelock(None),
        };
        Ok(tl)
    }
}

impl From<domain::Note> for Note {
    fn from(n: domain::Note) -> Self {
        Note {
            origin_page: Some(BlockHeight::from(n.head.origin_page)),
            timelock: match &n.head.timelock.0 {
                Some(_) => Some(TimeLockIntent::from(n.head.timelock)),
                None => None,
            },
            name: Some(Name::from(n.tail.name)),
            lock: Some(Lock::from(n.tail.lock)),
            source: Some(Source::from(n.tail.source)),
            assets: Some(Nicks::from(n.tail.assets)),
            version: Some(NoteVersion::from(n.head.version)),
        }
    }
}

impl TryFrom<Note> for domain::Note {
    type Error = ConversionError;
    fn try_from(n: Note) -> Result<Self, Self::Error> {
        Ok(domain::Note {
            head: domain::NoteHead {
                version: n.version.required("Note", "version")?.into(),
                origin_page: n.origin_page.required("Note", "origin_page")?.into(),
                timelock: n
                    .timelock
                    .map(TryInto::try_into)
                    .transpose()?
                    .unwrap_or(domain::Timelock(None)),
            },
            tail: domain::NoteTail {
                name: n.name.required("Note", "name")?.try_into()?,
                lock: n.lock.required("Note", "lock")?.try_into()?,
                source: n.source.required("Note", "source")?.try_into()?,
                assets: n.assets.required("Note", "assets")?.into(),
            },
        })
    }
}

impl TryFrom<WalletBalanceData> for domain::BalanceUpdate {
    type Error = anyhow::Error;

    fn try_from(update: WalletBalanceData) -> Result<Self> {
        let notes = update
            .notes
            .into_iter()
            .map(|entry| {
                let name: domain::Name = entry
                    .name
                    .required("WalletBalanceData", "name")?
                    .try_into()?;
                let note: domain::Note = entry
                    .note
                    .required("WalletBalanceData", "note")?
                    .try_into()?;
                Ok((name, note))
            })
            .collect::<Result<Vec<(domain::Name, domain::Note)>, Self::Error>>()?;
        Ok(domain::BalanceUpdate {
            notes: domain::Balance(notes),
            height: update
                .height
                .required("WalletBalanceData", "height")?
                .try_into()?,
            block_id: update
                .block_id
                .required("WalletBalanceData", "block_id")?
                .try_into()?,
        })
    }
}

impl TryFrom<domain::BalanceUpdate> for WalletBalanceData {
    type Error = ErrorStatus;

    fn try_from(update: domain::BalanceUpdate) -> Result<Self, Self::Error> {
        let notes = update
            .notes
            .0
            .into_iter()
            .map(|(name, note)| {
                Ok(BalanceEntry {
                    name: Some(Name::from(name)),
                    note: Some(Note::from(note)),
                })
            })
            .collect::<Result<Vec<_>, ErrorStatus>>()?;

        Ok(WalletBalanceData {
            notes,
            height: Some(BlockHeight::from(update.height)),
            block_id: Some(Hash::from(update.block_id)),
            page: Some(crate::pb::common::v1::PageResponse {
                next_page_token: String::new(),
            }),
        })
    }
}

impl TryFrom<domain::BalanceUpdate> for WalletGetBalanceResponse {
    type Error = ErrorStatus;

    fn try_from(update: domain::BalanceUpdate) -> Result<Self, Self::Error> {
        let balance_data = WalletBalanceData::try_from(update)?;
        Ok(WalletGetBalanceResponse {
            result: Some(wallet_get_balance_response::Result::Balance(balance_data)),
        })
    }
}

impl TryFrom<WalletGetBalanceResponse> for domain::BalanceUpdate {
    type Error = anyhow::Error;
    fn try_from(update: WalletGetBalanceResponse) -> Result<Self> {
        let update = update
            .result
            .required("WalletGetBalanceResponse", "result")?;
        match update {
            wallet_get_balance_response::Result::Balance(update) => {
                Ok(domain::BalanceUpdate::try_from(update)?)
            }
            wallet_get_balance_response::Result::Error(err) => Err(RPCErrorStatus::from(err))?,
        }
    }
}
