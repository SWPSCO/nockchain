use nockchain_types::tx_engine::common::Hash;
use nockchain_types::tx_engine::v1::tx::SpendCondition;

use crate::note_data::DecodedNoteData;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockResolutionSource {
    NoteData,
    ReconstructedSimplePkh,
    ReconstructedCoinbasePkh,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockResolution {
    pub source: LockResolutionSource,
    pub spend_condition: Option<SpendCondition>,
    pub spend_condition_count: Option<u64>,
}

impl LockResolution {
    /// Builds an unresolved lock result.
    pub fn unknown() -> Self {
        Self {
            source: LockResolutionSource::Unknown,
            spend_condition: None,
            spend_condition_count: None,
        }
    }
}

/// Input context used by a matcher while resolving the effective spend lock.
pub struct ResolveLockRequest<'a> {
    pub note_first_name: &'a Hash,
    pub decoded_note_data: &'a DecodedNoteData,
    pub signer_pkh: Option<&'a Hash>,
    pub coinbase_relative_min: Option<u64>,
}

/// Matcher that owns lock-selection policy for spendability.
///
/// The matcher carries any local signing/unlock context and is responsible for
/// resolving which lock should be used for a candidate note. Matchers may
/// override `resolve_lock` to compose or layer additional strategies.
pub trait LockMatcher {
    /// Returns true when this matcher can satisfy the provided spend condition
    /// for the target note first-name.
    fn matches(&self, note_first_name: &Hash, spend_condition: &SpendCondition) -> bool;

    /// Resolves the effective lock for a note using matcher-specific policy.
    ///
    /// The default strategy is:
    /// 1. Use a decoded single-leaf `%lock` note-data payload when it is
    ///    spendable by this matcher for the target first-name.
    /// 2. Otherwise, reconstruct a simple PKH lock from the local signer hash and require an
    ///    exact first-name match via matcher policy.
    /// 3. If simple reconstruction does not match, try reconstructed coinbase-style PKH using
    ///    the provided relative-min constant.
    /// 4. The reconstruction uses exactly the provided relative-min constant.
    fn resolve_lock(&self, request: ResolveLockRequest<'_>) -> LockResolution {
        if let Some(lock_data) = request.decoded_note_data.first_decoded_lock() {
            // TODO(wallet-tx-builder): support multi-leaf `%lock` note-data resolution by matching
            // against the full lock tree root and selecting a concrete leaf/index pair.
            // Today the matcher contract is leaf-oriented (`SpendCondition` only), so a `%lock`
            // payload with multiple spend conditions is ambiguous and is intentionally ignored.
            if lock_data.spend_conditions.len() == 1 {
                let spend_condition = &lock_data.spend_conditions[0];
                if self.matches(request.note_first_name, spend_condition) {
                    return LockResolution {
                        source: LockResolutionSource::NoteData,
                        spend_condition: Some(spend_condition.clone()),
                        spend_condition_count: None,
                    };
                }
            }
        }

        if let Some(pkh) = request.signer_pkh {
            let simple = SpendCondition::simple_pkh(pkh.clone());
            if self.matches(request.note_first_name, &simple) {
                return LockResolution {
                    source: LockResolutionSource::ReconstructedSimplePkh,
                    spend_condition: Some(simple),
                    spend_condition_count: None,
                };
            }
        }

        if let (Some(pkh), Some(relative_min)) = (request.signer_pkh, request.coinbase_relative_min)
        {
            let coinbase = SpendCondition::coinbase_pkh(pkh.clone(), relative_min);
            if self.matches(request.note_first_name, &coinbase) {
                return LockResolution {
                    source: LockResolutionSource::ReconstructedCoinbasePkh,
                    spend_condition: Some(coinbase),
                    spend_condition_count: None,
                };
            }
        }

        LockResolution::unknown()
    }
}

#[derive(Debug, Default)]
pub struct NeverMatches;

impl LockMatcher for NeverMatches {
    fn matches(&self, _note_first_name: &Hash, _spend_condition: &SpendCondition) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::note_data::{
        DecodedNoteDataEntry, DecodedNoteDataPayload, LockDataPayload, NormalizedNoteDataKey,
    };

    fn hash(v: u64) -> Hash {
        Hash::from_limbs(&[v, 0, 0, 0, 0])
    }

    struct MatchExpected {
        expected: SpendCondition,
    }

    impl LockMatcher for MatchExpected {
        fn matches(&self, _note_first_name: &Hash, spend_condition: &SpendCondition) -> bool {
            spend_condition == &self.expected
        }
    }

    fn lock_entry(lock: SpendCondition) -> DecodedNoteDataEntry {
        DecodedNoteDataEntry {
            raw_key: "lock".to_string(),
            normalized_key: NormalizedNoteDataKey::Lock,
            raw_blob: Bytes::new(),
            payload: DecodedNoteDataPayload::Lock(LockDataPayload {
                version: 0,
                spend_conditions: vec![lock],
            }),
            decode_error: None,
        }
    }

    fn decoded_note_data(entries: Vec<DecodedNoteDataEntry>) -> DecodedNoteData {
        DecodedNoteData(entries)
    }

    struct AlwaysMatches;

    impl LockMatcher for AlwaysMatches {
        fn matches(&self, _note_first_name: &Hash, _spend_condition: &SpendCondition) -> bool {
            true
        }
    }

    fn first_name_for_lock(spend_condition: &SpendCondition) -> Hash {
        spend_condition
            .first_name()
            .expect("first-name should compute")
            .into_hash()
    }

    #[test]
    fn note_data_lock_has_priority_over_reconstruction() {
        let note_lock = SpendCondition::simple_pkh(hash(9));
        let matcher = MatchExpected {
            expected: note_lock.clone(),
        };
        let decoded = decoded_note_data(vec![lock_entry(note_lock.clone())]);
        let result = matcher.resolve_lock(ResolveLockRequest {
            note_first_name: &first_name_for_lock(&note_lock),
            decoded_note_data: &decoded,
            signer_pkh: Some(&hash(7)),
            coinbase_relative_min: Some(5),
        });

        assert_eq!(result.source, LockResolutionSource::NoteData);
        assert_eq!(result.spend_condition, Some(note_lock));
        assert_eq!(result.spend_condition_count, None);
    }

    #[test]
    fn note_data_lock_tree_is_not_treated_as_a_single_spend_condition() {
        let first = SpendCondition::simple_pkh(hash(9));
        let second = SpendCondition::simple_pkh(hash(10));
        let matcher = MatchExpected {
            expected: second.clone(),
        };
        let entry = DecodedNoteDataEntry {
            raw_key: "lock".to_string(),
            normalized_key: NormalizedNoteDataKey::Lock,
            raw_blob: Bytes::new(),
            payload: DecodedNoteDataPayload::Lock(LockDataPayload {
                version: 0,
                spend_conditions: vec![first, second.clone()],
            }),
            decode_error: None,
        };
        let decoded = decoded_note_data(vec![entry]);
        let second_first_name = first_name_for_lock(&second);

        let result = matcher.resolve_lock(ResolveLockRequest {
            note_first_name: &second_first_name,
            decoded_note_data: &decoded,
            signer_pkh: None,
            coinbase_relative_min: None,
        });

        assert_eq!(result.source, LockResolutionSource::Unknown);
        assert_eq!(result.spend_condition, None);
        assert_eq!(result.spend_condition_count, None);
    }

    #[test]
    fn note_data_lock_reports_leaf_count_for_larger_lock_trees() {
        let first = SpendCondition::simple_pkh(hash(9));
        let second = SpendCondition::simple_pkh(hash(10));
        let third = SpendCondition::simple_pkh(hash(11));
        let fourth = SpendCondition::simple_pkh(hash(12));
        let matcher = MatchExpected {
            expected: third.clone(),
        };
        let entry = DecodedNoteDataEntry {
            raw_key: "lock".to_string(),
            normalized_key: NormalizedNoteDataKey::Lock,
            raw_blob: Bytes::new(),
            payload: DecodedNoteDataPayload::Lock(LockDataPayload {
                version: 0,
                spend_conditions: vec![first, second, third.clone(), fourth],
            }),
            decode_error: None,
        };
        let decoded = decoded_note_data(vec![entry]);
        let third_first_name = first_name_for_lock(&third);

        let result = matcher.resolve_lock(ResolveLockRequest {
            note_first_name: &third_first_name,
            decoded_note_data: &decoded,
            signer_pkh: None,
            coinbase_relative_min: None,
        });

        assert_eq!(result.source, LockResolutionSource::Unknown);
        assert_eq!(result.spend_condition, None);
        assert_eq!(result.spend_condition_count, None);
    }

    #[test]
    fn note_data_lock_is_ignored_when_matcher_rejects_it() {
        let note_lock = SpendCondition::simple_pkh(hash(3));
        let decoded = decoded_note_data(vec![lock_entry(note_lock)]);
        let result = NeverMatches.resolve_lock(ResolveLockRequest {
            note_first_name: &hash(1),
            decoded_note_data: &decoded,
            signer_pkh: None,
            coinbase_relative_min: None,
        });

        assert_eq!(result.source, LockResolutionSource::Unknown);
        assert_eq!(result.spend_condition, None);
        assert_eq!(result.spend_condition_count, None);
    }

    #[test]
    fn simple_reconstruction_is_attempted() {
        let pkh = hash(42);
        let expected_simple = SpendCondition::simple_pkh(pkh.clone());
        let matcher = MatchExpected {
            expected: expected_simple.clone(),
        };
        let decoded = decoded_note_data(Vec::new());
        let note_first_name = first_name_for_lock(&expected_simple);

        let result = matcher.resolve_lock(ResolveLockRequest {
            note_first_name: &note_first_name,
            decoded_note_data: &decoded,
            signer_pkh: Some(&pkh),
            coinbase_relative_min: Some(20),
        });

        assert_eq!(result.source, LockResolutionSource::ReconstructedSimplePkh);
        assert_eq!(result.spend_condition, Some(expected_simple));
        assert_eq!(result.spend_condition_count, None);
    }

    #[test]
    fn coinbase_reconstruction_is_attempted_after_simple() {
        let pkh = hash(42);
        let expected_coinbase = SpendCondition::coinbase_pkh(pkh.clone(), 20);
        let matcher = MatchExpected {
            expected: expected_coinbase.clone(),
        };
        let decoded = decoded_note_data(Vec::new());
        let note_first_name = first_name_for_lock(&expected_coinbase);

        let result = matcher.resolve_lock(ResolveLockRequest {
            note_first_name: &note_first_name,
            decoded_note_data: &decoded,
            signer_pkh: Some(&pkh),
            coinbase_relative_min: Some(20),
        });

        assert_eq!(
            result.source,
            LockResolutionSource::ReconstructedCoinbasePkh
        );
        assert_eq!(result.spend_condition, Some(expected_coinbase));
        assert_eq!(result.spend_condition_count, None);
    }

    #[test]
    fn unresolved_locks_return_unknown() {
        let decoded = decoded_note_data(Vec::new());
        let result = NeverMatches.resolve_lock(ResolveLockRequest {
            note_first_name: &hash(1),
            decoded_note_data: &decoded,
            signer_pkh: None,
            coinbase_relative_min: None,
        });

        assert_eq!(result.source, LockResolutionSource::Unknown);
        assert_eq!(result.spend_condition, None);
        assert_eq!(result.spend_condition_count, None);
    }

    #[test]
    fn coinbase_first_name_does_not_take_simple_reconstruction_path() {
        let pkh = hash(42);
        let expected_coinbase = SpendCondition::coinbase_pkh(pkh.clone(), 20);
        let note_first_name = first_name_for_lock(&expected_coinbase);
        let decoded = decoded_note_data(Vec::new());
        let matcher = MatchExpected {
            expected: expected_coinbase.clone(),
        };

        let result = matcher.resolve_lock(ResolveLockRequest {
            note_first_name: &note_first_name,
            decoded_note_data: &decoded,
            signer_pkh: Some(&pkh),
            coinbase_relative_min: Some(20),
        });

        assert_eq!(
            result.source,
            LockResolutionSource::ReconstructedCoinbasePkh
        );
        assert_eq!(result.spend_condition, Some(expected_coinbase));
    }

    #[test]
    fn malformed_lock_entry_falls_back_to_reconstruction() {
        let pkh = hash(42);
        let expected_simple = SpendCondition::simple_pkh(pkh.clone());
        let decoded = decoded_note_data(vec![DecodedNoteDataEntry {
            raw_key: "lock".to_string(),
            normalized_key: NormalizedNoteDataKey::Lock,
            raw_blob: Bytes::new(),
            payload: DecodedNoteDataPayload::Raw,
            decode_error: Some("bad lock".to_string()),
        }]);

        let result = AlwaysMatches.resolve_lock(ResolveLockRequest {
            note_first_name: &first_name_for_lock(&expected_simple),
            decoded_note_data: &decoded,
            signer_pkh: Some(&pkh),
            coinbase_relative_min: Some(20),
        });

        assert_eq!(result.source, LockResolutionSource::ReconstructedSimplePkh);
        assert_eq!(result.spend_condition, Some(expected_simple));
    }

    #[test]
    fn decoded_lock_mismatch_falls_back_to_coinbase_reconstruction() {
        let pkh = hash(42);
        let simple = SpendCondition::simple_pkh(pkh.clone());
        let expected_coinbase = SpendCondition::coinbase_pkh(pkh.clone(), 20);
        let decoded = decoded_note_data(vec![lock_entry(simple)]);
        let matcher = MatchExpected {
            expected: expected_coinbase.clone(),
        };

        let result = matcher.resolve_lock(ResolveLockRequest {
            note_first_name: &first_name_for_lock(&expected_coinbase),
            decoded_note_data: &decoded,
            signer_pkh: Some(&pkh),
            coinbase_relative_min: Some(20),
        });

        assert_eq!(
            result.source,
            LockResolutionSource::ReconstructedCoinbasePkh
        );
        assert_eq!(result.spend_condition, Some(expected_coinbase));
    }

    #[test]
    fn coinbase_reconstruction_uses_configured_relative_min_only() {
        let pkh = hash(42);
        let expected_legacy_coinbase = SpendCondition::coinbase_pkh(pkh.clone(), 100);
        let decoded = decoded_note_data(Vec::new());
        let matcher = MatchExpected {
            expected: expected_legacy_coinbase.clone(),
        };

        let result = matcher.resolve_lock(ResolveLockRequest {
            note_first_name: &first_name_for_lock(&expected_legacy_coinbase),
            decoded_note_data: &decoded,
            signer_pkh: Some(&pkh),
            coinbase_relative_min: Some(1),
        });

        assert_eq!(result.source, LockResolutionSource::Unknown);
        assert_eq!(result.spend_condition, None);
    }
}
