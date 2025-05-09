use thiserror::Error;

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Wallet error: {0}")]
    Generic(String),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("NockApp error: {0}")]
    NockAppError(#[from] crown::nockapp::NockAppError),
    
    #[error("Crown error: {0}")]
    CrownError(#[from] crown::CrownError),
}

impl WalletError {
    pub fn generic<S: Into<String>>(msg: S) -> Self {
        WalletError::Generic(msg.into())
    }
    
    pub fn invalid_input<S: Into<String>>(msg: S) -> Self {
        WalletError::InvalidInput(msg.into())
    }
    
    pub fn serialization_error<S: Into<String>>(msg: S) -> Self {
        WalletError::SerializationError(msg.into())
    }
}
