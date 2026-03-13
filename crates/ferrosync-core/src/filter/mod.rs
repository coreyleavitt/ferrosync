//! Include/exclude/filter rule engine.
//!
//! Implements rsync's filter rule syntax for selecting which files to
//! transfer. Rules are evaluated in order; the first matching rule wins.
//!
//! Rule syntax:
//! - `- pattern` -- exclude
//! - `+ pattern` -- include
//! - `--exclude=PATTERN` / `--include=PATTERN` on the command line
//!
//! Pattern syntax (rsync-compatible):
//! - `*` matches any path component (not `/`)
//! - `**` matches anything including `/`
//! - `?` matches any single character (not `/`)
//! - `[...]` character class
//! - Leading `/` anchors to the transfer root
//! - Trailing `/` matches only directories

mod pattern;
mod rule;

pub use pattern::Pattern;
pub use rule::{FilterAction, FilterRule, FilterRuleList};
