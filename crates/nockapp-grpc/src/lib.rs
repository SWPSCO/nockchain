//! gRPC server implementation for NockApp
//!
//! This crate provides a gRPC interface to NockApp, replacing the old socket-based
//! interface with modern RPC patterns for easier cross-language compatibility.

// Include the generated protobuf code

pub mod error;
pub mod pagination;
pub mod services;
#[cfg(test)]
mod tests;
pub mod wire_conversion;

pub use error::{NockAppGrpcError, Result};
pub use nockapp_grpc_proto::{convert, pb};
pub use services::{private_nockapp, public_nockchain};

// Backcompat re-export: allow imports like `nockapp_grpc::driver::...`
pub mod driver {
    pub use crate::services::public_nockchain::driver::{grpc_listener_driver, grpc_server_driver};
}
