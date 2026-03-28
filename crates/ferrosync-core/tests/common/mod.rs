// Shared test utilities. Not every test file uses every item, so allow dead_code
// to avoid warnings when a test file only uses a subset.
#![allow(dead_code)]

pub mod assertions;
pub mod env;
pub mod ssh;

// Re-export commonly used types to avoid verbose qualified paths in tests.
pub use ferrosync_core::options::{DeleteMode, TransferOptions};
