//! Transfer engine: generator, sender, receiver pipeline.
//!
//! The engine orchestrates rsync's three-role transfer pipeline:
//!
//! - **Generator**: Iterates the file list, reads basis files, computes block
//!   signatures, sends them to the sender.
//! - **Sender**: Receives block signatures, matches against source files,
//!   sends delta tokens to the receiver.
//! - **Receiver**: Receives delta tokens, reconstructs files from basis +
//!   delta, verifies file-level checksums.

pub mod batch;
pub mod delete;
pub mod file_decision;
pub mod generator;
pub mod pipeline;
pub mod progress;
pub mod receiver;
pub mod receiver_engine;
pub mod sender;
pub mod session;
pub mod transfer;
pub mod wire_transfer;
