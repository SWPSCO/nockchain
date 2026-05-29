use libp2p::PeerId;
use nockapp::noun::slab::NounSlab;
use nockapp::NockAppError;
use nockvm::noun::{Noun, NounAllocator, NounHandle, NounSpace, D};
use nockvm_macros::tas;
use serde_bytes::ByteBuf;

use crate::p2p_util::PeerIdExt;
use crate::tip5_util::{tip5_hash_to_base58, tip5_hash_to_base58_stack};

const POKE_VERSION: u64 = 0;

#[derive(Debug, Clone)]
pub enum NockchainFact {
    // [%heard-block p=page:dt] with poke slab
    HeardBlock(String, NounSlab),
    // [%heard-elders p=[oldest=page-number:dt ids=(list block-id:dt)]] with poke slab
    HeardElders(u64, Vec<String>, NounSlab),
    // [%heard-tx p=raw-tx:dt] with poke slab
    HeardTx(String, NounSlab),
}

impl NockchainFact {
    pub fn from_noun_slab(slab: &mut NounSlab) -> Result<Self, NockAppError> {
        let mut poke_slab = NounSlab::new();

        poke_slab.copy_from_slab(slab);
        poke_slab.modify(|response_noun| vec![D(tas!(b"fact")), D(POKE_VERSION), response_noun]);

        let noun = unsafe { slab.root() };
        let space = slab.noun_space();
        let head = noun.in_space(&space).as_cell()?.head();

        if head.eq_bytes(b"heard-block") {
            let page = noun.in_space(&space).as_cell()?.tail();
            let block_id = block_id_from_page(page)?;
            let block_id_str = tip5_hash_to_base58_stack(slab, block_id.noun(), block_id.space())?;
            Ok(NockchainFact::HeardBlock(block_id_str, poke_slab))
        } else if head.eq_bytes(b"heard-tx") {
            let raw_tx = noun.in_space(&space).as_cell()?.tail();
            let tx_id = tx_id_from_raw_tx(raw_tx)?;
            let tx_id_str = tip5_hash_to_base58_stack(slab, tx_id.noun(), tx_id.space())?;
            Ok(NockchainFact::HeardTx(tx_id_str, poke_slab))
        } else if head.eq_bytes(b"heard-elders") {
            let elders_noun = noun.in_space(&space).as_cell()?.tail().noun();
            let elders_dat = elders_noun.in_space(&space);
            let elders_cell = elders_dat.as_cell()?;
            let oldest = elders_cell.head().as_atom()?.as_u64()?;
            let elder_ids = elders_cell.tail();
            // Need to handle the closure capturing mutable reference
            let mut elder_id_strings = Vec::new();
            for id_noun in elder_ids.list_iter() {
                elder_id_strings.push(tip5_hash_to_base58_stack(slab, id_noun.noun(), &space)?);
            }
            Ok(NockchainFact::HeardElders(
                oldest, elder_id_strings, poke_slab,
            ))
        } else {
            Err(NockAppError::OtherError(String::from(
                "Invalid fact head tag",
            )))
        }
    }
    pub fn fact_poke(&self) -> &NounSlab {
        match self {
            Self::HeardBlock(_, slab) => slab,
            Self::HeardTx(_, slab) => slab,
            Self::HeardElders(_, _, slab) => slab,
        }
    }
}

fn block_id_from_page<'a>(page: NounHandle<'a>) -> Result<NounHandle<'a>, NockAppError> {
    let page_cell = page.as_cell()?;
    // page v0: [block-id ...]
    // page v1: [%1 block-id ...]
    match page_cell.head().as_atom() {
        Ok(version_atom) => {
            let version = version_atom.as_u64()?;
            if version == 1 {
                return Ok(page_cell.tail().as_cell()?.head());
            }
            Err(NockAppError::OtherError(format!(
                "Unsupported page version {}",
                version
            )))
        }
        Err(_) => Ok(page_cell.head()),
    }
}

fn tx_id_from_raw_tx<'a>(raw_tx: NounHandle<'a>) -> Result<NounHandle<'a>, NockAppError> {
    let raw_tx_cell = raw_tx.as_cell()?;
    // raw-tx v0: [tx-id ...]
    // raw-tx v1: [%1 tx-id ...]
    match raw_tx_cell.head().as_atom() {
        Ok(version_atom) => {
            let version = version_atom.as_u64()?;
            if version == 1 {
                return Ok(raw_tx_cell.tail().as_cell()?.head());
            }
            Err(NockAppError::OtherError(format!(
                "Unsupported raw-tx version {}",
                version
            )))
        }
        Err(_) => Ok(raw_tx_cell.head()),
    }
}

#[derive(Debug, Clone)]
pub enum NockchainDataRequest {
    BlockByHeight(u64), // Height requested
    #[allow(dead_code)]
    EldersById(String, PeerId, NounSlab), // Block ID as string, peer id, block id as noun,
    #[allow(dead_code)]
    RawTransactionById(String, NounSlab), // transaction id as string, transaction id as noun,
}

impl NockchainDataRequest {
    /// Takes noun of type [%request p=request]
    pub fn from_noun(noun: Noun, space: &NounSpace) -> Result<Self, NockAppError> {
        let res = (|| {
            let request_cell = noun.in_space(space).as_cell()?;
            if !request_cell.head().eq_bytes(b"request") {
                return Err(NockAppError::OtherError(String::from(
                    "Missing %request tag",
                )));
            }
            // kind cell type $%([%block request-block] [%raw-tx request-tx])
            let kind_cell = request_cell.tail().as_cell()?;
            if kind_cell.head().eq_bytes(b"block") {
                // block_cell type
                // $%  [%by-height p=page-number:dt]
                //     [%elders p=block-id:dt q=peer-id]
                // ==
                let block_cell = kind_cell.tail().as_cell()?;
                if block_cell.head().eq_bytes(b"by-height") {
                    let height = block_cell.tail().as_atom()?.as_u64()?;
                    Ok(Self::BlockByHeight(height))
                } else if block_cell.head().eq_bytes(b"elders") {
                    let elders_cell = block_cell.tail().as_cell()?;
                    let block_id = tip5_hash_to_base58(elders_cell.head().noun(), space)?;
                    let peer_id = PeerId::from_noun(elders_cell.tail().noun(), space)?;
                    let slab = {
                        let mut slab = NounSlab::new();
                        slab.copy_into(elders_cell.head().noun(), space);
                        slab
                    };
                    Ok(Self::EldersById(block_id, peer_id, slab))
                } else {
                    Err(NockAppError::OtherError(String::from(
                        "Failed to parse EldersById message",
                    )))
                }
            } else if kind_cell.head().eq_bytes(b"raw-tx") {
                // has type [%by-id p=tx-id:dt]
                let raw_tx_cell = kind_cell.tail().as_cell()?;
                let raw_tx_id = tip5_hash_to_base58(raw_tx_cell.tail().noun(), space)?;
                let slab = {
                    let mut slab = NounSlab::new();
                    slab.copy_into(raw_tx_cell.tail().noun(), space);
                    slab
                };
                Ok(Self::RawTransactionById(raw_tx_id, slab))
            } else {
                Err(NockAppError::OtherError(String::from(
                    "Failed to parse RawTransaction message",
                )))
            }
        })();
        res.map_err(|_| NockAppError::IoError(std::io::Error::other("bad request")))
    }
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
/// Network struct (in serde/CBOR) for requests
pub enum NockchainRequest {
    /// Request a block or TX from another node, carry PoW
    Request {
        pow: equix::SolutionByteArray,
        nonce: u64,
        message: ByteBuf,
    },
    /// Gossip a block or TX to another node
    Gossip { message: ByteBuf },
}

impl NockchainRequest {
    /// Make a new "request" which gossips a block or a TX
    pub(crate) fn new_gossip(message: &NounSlab) -> NockchainRequest {
        let message_bytes = ByteBuf::from(message.jam().as_ref());
        NockchainRequest::Gossip {
            message: message_bytes,
        }
    }

    /// Make a new request for a block or a TX
    pub(crate) fn new_request(
        builder: &mut equix::EquiXBuilder,
        local_peer_id: &libp2p::PeerId,
        remote_peer_id: &libp2p::PeerId,
        message: &NounSlab,
    ) -> NockchainRequest {
        let message_bytes = ByteBuf::from(message.jam().as_ref());
        let local_peer_bytes = (*local_peer_id).to_bytes();
        let remote_peer_bytes = (*remote_peer_id).to_bytes();
        let mut pow_buf = Vec::with_capacity(
            size_of::<u64>()
                + local_peer_bytes.len()
                + remote_peer_bytes.len()
                + message_bytes.len(),
        );
        pow_buf.extend_from_slice(&[0; size_of::<u64>()][..]);
        pow_buf.extend_from_slice(&local_peer_bytes[..]);
        pow_buf.extend_from_slice(&remote_peer_bytes[..]);
        pow_buf.extend_from_slice(&message_bytes[..]);

        let mut nonce = 0u64;
        let sol_bytes = loop {
            {
                let nonce_buf = &mut pow_buf[0..size_of::<u64>()];
                nonce_buf.copy_from_slice(&nonce.to_le_bytes()[..]);
            }
            if let Ok(sols) = builder.solve(&pow_buf[..]) {
                if !sols.is_empty() {
                    break sols[0].to_bytes();
                }
            }
            nonce += 1;
        };

        NockchainRequest::Request {
            pow: sol_bytes,
            nonce,
            message: message_bytes,
        }
    }

    /// Verify the EquiX PoW attached to a request
    pub(crate) fn verify_pow(
        &self,
        builder: &mut equix::EquiXBuilder,
        local_peer_id: &libp2p::PeerId,
        remote_peer_id: &libp2p::PeerId,
    ) -> Result<(), equix::Error> {
        match self {
            NockchainRequest::Request {
                pow,
                nonce,
                message,
            } => {
                //  This looks backwards, but it's because which node is local and which is remote
                //  is swapped between generation at the sender and verification at the receiver.
                let local_peer_bytes = (*remote_peer_id).to_bytes();
                let remote_peer_bytes = (*local_peer_id).to_bytes();
                let nonce_bytes = nonce.to_le_bytes();
                let mut pow_buf = Vec::with_capacity(
                    size_of::<u64>()
                        + local_peer_bytes.len()
                        + remote_peer_bytes.len()
                        + message.len(),
                );
                pow_buf.extend_from_slice(&nonce_bytes[..]);
                pow_buf.extend_from_slice(&local_peer_bytes[..]);
                pow_buf.extend_from_slice(&remote_peer_bytes[..]);
                pow_buf.extend_from_slice(&message[..]);
                builder.verify_bytes(&pow_buf[..], pow)
            }
            NockchainRequest::Gossip { message: _ } => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
/// Responses to Nockchain requests
pub enum NockchainResponse {
    /// The requested block or raw-tx
    Result { message: ByteBuf },
    /// If the request was a gossip, no actual response is needed
    Ack { acked: bool },
}

impl NockchainResponse {
    pub(crate) fn new_response_result(message: impl AsRef<[u8]>) -> NockchainResponse {
        let message_bytes: &[u8] = message.as_ref();
        let message_bytebuf = ByteBuf::from(message_bytes.to_vec());
        NockchainResponse::Result {
            message: message_bytebuf,
        }
    }
}

#[cfg(test)]
mod tests {
    use nockapp::utils::make_tas;
    use nockvm::noun::T;

    use super::*;

    #[test]
    fn test_block_id_from_page_supports_v0_and_v1() {
        let mut slab: NounSlab = NounSlab::new();
        let block_id = T(&mut slab, &[D(1), D(2), D(3), D(4), D(5)]);
        let v0_page = T(&mut slab, &[block_id, D(99)]);
        let v1_page = T(&mut slab, &[D(1), block_id, D(99)]);
        let space = slab.noun_space();

        let v0 = block_id_from_page(v0_page.in_space(&space)).expect("v0 page should decode");
        let v1 = block_id_from_page(v1_page.in_space(&space)).expect("v1 page should decode");

        assert!(unsafe { v0.noun().raw_equals(&block_id) });
        assert!(unsafe { v1.noun().raw_equals(&block_id) });
    }

    #[test]
    fn test_tx_id_from_raw_tx_supports_v0_and_v1() {
        let mut slab: NounSlab = NounSlab::new();
        let tx_id = T(&mut slab, &[D(6), D(7), D(8), D(9), D(10)]);
        let v0_raw_tx = T(&mut slab, &[tx_id, D(11)]);
        let v1_raw_tx = T(&mut slab, &[D(1), tx_id, D(11)]);
        let space = slab.noun_space();

        let v0 = tx_id_from_raw_tx(v0_raw_tx.in_space(&space)).expect("v0 raw-tx should decode");
        let v1 = tx_id_from_raw_tx(v1_raw_tx.in_space(&space)).expect("v1 raw-tx should decode");

        assert!(unsafe { v0.noun().raw_equals(&tx_id) });
        assert!(unsafe { v1.noun().raw_equals(&tx_id) });
    }

    #[test]
    fn test_from_noun_slab_extracts_v1_block_and_tx_ids() {
        let mut block_slab: NounSlab = NounSlab::new();
        let block_id = T(&mut block_slab, &[D(1), D(2), D(3), D(4), D(5)]);
        let block_page = T(&mut block_slab, &[D(1), block_id, D(0)]);
        let heard_block_tag = make_tas(&mut block_slab, "heard-block").as_noun();
        let heard_block = T(&mut block_slab, &[heard_block_tag, block_page]);
        block_slab.set_root(heard_block);
        let block_space = block_slab.noun_space();
        let expected_block_id =
            tip5_hash_to_base58(block_id, &block_space).expect("block id should encode");

        let parsed_block =
            NockchainFact::from_noun_slab(&mut block_slab).expect("heard-block should parse");
        match parsed_block {
            NockchainFact::HeardBlock(id, poke) => {
                assert_eq!(id, expected_block_id);
                let poke_space = poke.noun_space();
                assert!(unsafe { poke.root().in_space(&poke_space).as_cell().is_ok() });
            }
            other => panic!("expected HeardBlock, got {other:?}"),
        }

        let mut tx_slab: NounSlab = NounSlab::new();
        let tx_id = T(&mut tx_slab, &[D(6), D(7), D(8), D(9), D(10)]);
        let raw_tx = T(&mut tx_slab, &[D(1), tx_id, D(0)]);
        let heard_tx_tag = make_tas(&mut tx_slab, "heard-tx").as_noun();
        let heard_tx = T(&mut tx_slab, &[heard_tx_tag, raw_tx]);
        tx_slab.set_root(heard_tx);
        let tx_space = tx_slab.noun_space();
        let expected_tx_id = tip5_hash_to_base58(tx_id, &tx_space).expect("tx id should encode");

        let parsed_tx = NockchainFact::from_noun_slab(&mut tx_slab).expect("heard-tx should parse");
        match parsed_tx {
            NockchainFact::HeardTx(id, poke) => {
                assert_eq!(id, expected_tx_id);
                let poke_space = poke.noun_space();
                assert!(unsafe { poke.root().in_space(&poke_space).as_cell().is_ok() });
            }
            other => panic!("expected HeardTx, got {other:?}"),
        }
    }
}
