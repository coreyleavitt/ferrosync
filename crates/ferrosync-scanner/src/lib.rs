//! File list scanner with composable enrichers for ferrosync.
//!
//! This crate provides `FileListScanner`, a composable pipeline for walking
//! directories, applying filter rules, and enriching entries with metadata
//! (symlink targets, ACLs, xattrs, hardlink groups).

mod scanner;
pub mod walk;

pub use scanner::*;
