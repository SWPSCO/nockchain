use crate::{JammedNoun, NounExt};
use bincode::config::{self, Configuration};
use bincode::{encode_to_vec, Decode, Encode};
use blake3::{Hash, Hasher};
use bytes::Bytes;
use nockvm::jets::cold::{Cold, Nounable};
use nockvm::mem::NockStack;
use nockvm::noun::Noun;
use nockvm_macros::tas;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, error, warn};

#[derive(Clone)]
pub struct Checkpoint {
    /// Magic bytes to identify checkpoint format
    pub magic_bytes: u64,
    /// Version of checkpoint
    pub version: u32,
    /// The buffer that this checkpoint was saved to, either 0 or 1.
    pub buff_index: bool,
    /// Hash of the boot kernel
    pub ker_hash: Hash,
    /// Event number
    pub event_num: u64,
    /// State of the kernel
    pub ker_state: Noun,
    /// Cold state
    pub cold: Cold,
}

impl std::fmt::Debug for Checkpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Checkpoint")
            .field("magic_bytes", &self.magic_bytes)
            .field("version", &self.version)
            .field("buff_index", &self.buff_index)
            .field("ker_hash", &self.ker_hash)
            .field("event_num", &self.event_num)
            .field("ker_state", &self.ker_state)
            .finish()
    }
}

impl Checkpoint {
    pub fn load(stack: &mut NockStack, jam: JammedCheckpoint) -> Result<Self, CheckpointError> {
        let cell = <Noun as NounExt>::cue_bytes(stack, &jam.jam.0)
            .map_err(|_| CheckpointError::SwordInterpreterError)?
            .as_cell()?;

        let cold_mem = Cold::from_noun(stack, &cell.tail())?;
        let cold = Cold::from_vecs(stack, cold_mem.0, cold_mem.1, cold_mem.2);

        Ok(Self {
            magic_bytes: jam.magic_bytes,
            version: jam.version,
            buff_index: jam.buff_index,
            ker_hash: jam.ker_hash,
            event_num: jam.event_num,
            ker_state: cell.head(),
            cold,
        })
    }
}

#[derive(Encode, Decode, PartialEq, Debug)]
pub struct JammedCheckpoint {
    /// Magic bytes to identify checkpoint format
    pub magic_bytes: u64,
    /// Version of checkpoint
    pub version: u32,
    /// The buffer this checkpoint was saved to, either 0 or 1
    pub buff_index: bool,
    /// Hash of the boot kernel
    #[bincode(with_serde)]
    pub ker_hash: Hash,
    /// Checksum derived from event_num and jam (the entries below)
    #[bincode(with_serde)]
    pub checksum: Hash,
    /// Event number
    pub event_num: u64,
    /// Jammed noun of [kernel_state cold_state]
    pub jam: JammedNoun,
}

/// A structure for exporting just the kernel state, without the cold state
#[derive(Encode, Decode, PartialEq, Debug)]
pub struct ExportedState {
    /// Magic bytes to identify exported state format
    pub magic_bytes: u64,
    /// Version of exported state
    pub version: u32,
    /// Hash of the boot kernel
    #[bincode(with_serde)]
    pub ker_hash: Hash,
    /// Event number
    pub event_num: u64,
    /// Jammed noun of kernel_state
    pub jam: JammedNoun,
}

impl ExportedState {
    pub fn new(
        stack: &mut NockStack,
        version: u32,
        ker_hash: Hash,
        event_num: u64,
        ker_state: &Noun,
    ) -> Self {
        let jam = JammedNoun::from_noun(stack, *ker_state);
        Self {
            magic_bytes: tas!(b"EXPJAM"),
            version,
            ker_hash,
            event_num,
            jam,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, bincode::error::EncodeError> {
        encode_to_vec(self, config::standard())
    }
}

impl JammedCheckpoint {
    pub fn new(
        version: u32,
        buff_index: bool,
        ker_hash: Hash,
        event_num: u64,
        jam: JammedNoun,
    ) -> Self {
        let checksum = Self::checksum(event_num, &jam.0);
        Self {
            magic_bytes: tas!(b"CHKJAM"),
            version,
            buff_index,
            ker_hash,
            checksum,
            event_num,
            jam,
        }
    }
    pub fn validate(&self) -> bool {
        self.checksum == Self::checksum(self.event_num, &self.jam.0)
    }
    pub fn encode(&self) -> Result<Vec<u8>, bincode::error::EncodeError> {
        encode_to_vec(self, config::standard())
    }
    fn checksum(event_num: u64, jam: &Bytes) -> Hash {
        let jam_len = jam.len();
        let mut hasher = Hasher::new();
        hasher.update(&event_num.to_le_bytes());
        hasher.update(&jam_len.to_le_bytes());
        hasher.update(jam);
        hasher.finalize()
    }
}

#[derive(Error, Debug)]
pub enum CheckpointError<'a> {
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Bincode error: {0}")]
    DecodeError(#[from] bincode::error::DecodeError),
    #[error("Invalid checksum at {0}")]
    InvalidChecksum(&'a PathBuf),
    #[error("Sword noun error: {0}")]
    SwordNounError(#[from] nockvm::noun::Error),
    #[error("Sword cold error: {0}")]
    FromNounError(#[from] nockvm::jets::cold::FromNounError),
    #[error("Both checkpoints failed: {0}, {1}")]
    BothCheckpointsFailed(Box<CheckpointError<'a>>, Box<CheckpointError<'a>>),
    #[error("Sword interpreter error")]
    SwordInterpreterError,
}

#[derive(Debug, Clone)]
pub struct JamPaths(pub PathBuf, pub PathBuf);

impl JamPaths {
    pub fn new(dir: &Path) -> Self {
        let path_0 = dir.join("0.chkjam");
        let path_1 = dir.join("1.chkjam");
        debug!("JamPaths created: path_0={}, path_1={}", path_0.display(), path_1.display());
        Self(path_0, path_1)
    }

    pub fn checkpoint_exists(&self) -> bool {
        let exists_0 = self.0.exists();
        let exists_1 = self.1.exists();
        debug!("Checkpoint existence check: {} exists={}, {} exists={}", 
               self.0.display(), exists_0, self.1.display(), exists_1);
        exists_0 || exists_1
    }

    pub fn load_checkpoint<'a>(
        &'a self,
        stack: &'a mut NockStack,
    ) -> Result<Checkpoint, CheckpointError<'a>> {
        debug!("Starting checkpoint load from paths: {} and {}", self.0.display(), self.1.display());
        
        debug!("Attempting to decode checkpoint 0: {}", self.0.display());
        let chk_0 = Self::decode_jam(&self.0);
        if let Err(ref e) = chk_0 {
            debug!("Failed to decode checkpoint 0: {}", e);
        } else {
            debug!("Successfully decoded checkpoint 0");
        }

        debug!("Attempting to decode checkpoint 1: {}", self.1.display());
        let chk_1 = Self::decode_jam(&self.1);
        if let Err(ref e) = chk_1 {
            debug!("Failed to decode checkpoint 1: {}", e);
        } else {
            debug!("Successfully decoded checkpoint 1");
        }

        match (chk_0, chk_1) {
            (Ok(a), Ok(b)) => {
                debug!("Both checkpoints loaded successfully");
                let chosen = if a.event_num > b.event_num {
                    debug!(
                        "Choosing checkpoint 0 (event_num: {} > {}): {}, checksum: {}",
                        a.event_num, b.event_num, self.0.display(), a.checksum
                    );
                    a
                } else {
                    debug!(
                        "Choosing checkpoint 1 (event_num: {} >= {}): {}, checksum: {}",
                        b.event_num, a.event_num, self.1.display(), b.checksum
                    );
                    b
                };
                debug!("Loading chosen checkpoint into memory");
                Checkpoint::load(stack, chosen)
            }
            (Ok(c), Err(e)) => {
                warn!("Checkpoint 1 failed, using checkpoint 0: {}", e);
                debug!("Loading checkpoint 0, checksum: {}", c.checksum);
                Checkpoint::load(stack, c)
            }
            (Err(e), Ok(c)) => {
                warn!("Checkpoint 0 failed, using checkpoint 1: {}", e);
                debug!("Loading checkpoint 1, checksum: {}", c.checksum);
                Checkpoint::load(stack, c)
            }
            (Err(e1), Err(e2)) => {
                error!("Both checkpoints failed to load!");
                error!("Checkpoint 0 error: {}", e1);
                error!("Checkpoint 1 error: {}", e2);
                debug!("Returning BothCheckpointsFailed error");
                Err(CheckpointError::BothCheckpointsFailed(
                    Box::new(e1),
                    Box::new(e2),
                ))
            }
        }
    }

    pub fn decode_jam(jam_path: &PathBuf) -> Result<JammedCheckpoint, CheckpointError> {
        debug!("decode_jam: Attempting to read file: {}", jam_path.display());
        
        if !jam_path.exists() {
            debug!("decode_jam: File does not exist: {}", jam_path.display());
            return Err(CheckpointError::IOError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Checkpoint file not found: {}", jam_path.display())
            )));
        }

        debug!("decode_jam: File exists, attempting to read");
        let jam: Vec<u8> = match std::fs::read(jam_path.as_path()) {
            Ok(data) => {
                debug!("decode_jam: Successfully read {} bytes from {}", data.len(), jam_path.display());
                data
            }
            Err(e) => {
                error!("decode_jam: Failed to read file {}: {}", jam_path.display(), e);
                return Err(CheckpointError::IOError(e));
            }
        };

        debug!("decode_jam: Attempting to decode bincode data");
        let config = bincode::config::standard();
        let (checkpoint, _) = match bincode::decode_from_slice::<JammedCheckpoint, Configuration>(&jam, config) {
            Ok(result) => {
                debug!("decode_jam: Successfully decoded bincode data");
                result
            }
            Err(e) => {
                error!("decode_jam: Failed to decode bincode data: {}", e);
                return Err(CheckpointError::DecodeError(e));
            }
        };

        debug!("decode_jam: Validating checkpoint");
        if checkpoint.validate() {
            debug!("decode_jam: Checkpoint validation successful");
            Ok(checkpoint)
        } else {
            error!("decode_jam: Checkpoint validation failed for {}", jam_path.display());
            Err(CheckpointError::InvalidChecksum(jam_path))
        }
    }
}
