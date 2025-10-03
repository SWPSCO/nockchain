mod cache;
pub mod client;
pub mod driver;
pub mod metrics;
pub mod server;

pub use client::PublicNockchainGrpcClient;
pub use driver::{grpc_listener_driver, grpc_server_driver};
pub use server::PublicNockchainGrpcServer;

#[cfg(test)]
pub(crate) mod fixtures {
    use nockchain_math::belt::Belt;
    use nockchain_math::crypto::cheetah::A_GEN;
    use nockchain_types::tx_engine::note::{
        Balance, BalanceUpdate, BlockHeight, Hash, Lock, Name, Nicks, Note, NoteHead, NoteTail,
        Source, Timelock, Version,
    };
    use nockchain_types::SchnorrPubkey;

    pub fn make_balance_update(count: usize) -> (BalanceUpdate, Vec<Name>) {
        let mut notes = Vec::with_capacity(count);
        let mut names = Vec::with_capacity(count);

        for idx in (0..count).rev() {
            let (name, note) = make_named_note(idx as u64);
            names.push(name.clone());
            notes.push((name, note));
        }

        let update = BalanceUpdate {
            height: BlockHeight(Belt((count as u64) + 1)),
            block_id: make_hash(99),
            notes: Balance(notes),
        };

        (update, names)
    }

    pub fn make_named_note(seed: u64) -> (Name, Note) {
        let name = Name::new(make_hash(seed * 2 + 1), make_hash(seed * 2 + 2));

        let head = NoteHead {
            version: Version::V0,
            origin_page: BlockHeight(Belt(seed)),
            timelock: Timelock(None),
        };

        let tail = NoteTail {
            name: name.clone(),
            lock: Lock {
                keys_required: 1,
                pubkeys: vec![SchnorrPubkey(A_GEN)],
            },
            source: Source {
                hash: make_hash(seed * 3 + 7),
                is_coinbase: false,
            },
            assets: Nicks(seed as usize),
        };

        (name.clone(), Note { head, tail })
    }

    pub fn make_hash(seed: u64) -> Hash {
        Hash([Belt(seed + 1), Belt(seed + 2), Belt(seed + 3), Belt(seed + 4), Belt(seed + 5)])
    }
}
