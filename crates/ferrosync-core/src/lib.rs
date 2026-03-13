pub mod delta;
pub mod engine;
pub mod error;
pub mod filelist;
pub mod filter;
pub mod fs;
pub mod options;
pub mod protocol;
pub mod stats;
pub mod transport;

pub use error::FerrosyncError;
pub type Result<T> = std::result::Result<T, FerrosyncError>;
