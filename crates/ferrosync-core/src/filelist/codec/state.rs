//! Delta state shared between encoder and decoder.
//!
//! Each file entry is delta-encoded against the previous entry's fields.
//! `DeltaState` tracks the "previous" values across sequential calls.

use crate::filelist::entry::FileEntry;

/// Delta state maintained across sequential file entry encode/decode calls.
#[derive(Debug, Clone, Default)]
pub struct DeltaState {
    /// Previous entry's full filename (for prefix compression).
    pub prev_name: Vec<u8>,
    /// Previous modification time.
    pub prev_mtime: i64,
    /// Previous file mode.
    pub prev_mode: u32,
    /// Previous uid.
    pub prev_uid: u32,
    /// Previous gid.
    pub prev_gid: u32,
    /// Previous device number (major << 8 | minor).
    pub prev_rdev: u64,
    /// Previous rdev major.
    pub prev_rdev_major: u32,
    /// Previous username.
    pub prev_user_name: Vec<u8>,
    /// Previous group name.
    pub prev_group_name: Vec<u8>,
    /// Starting NDX of the current sub-flist (0 for batch mode, >= 1 for
    /// incremental). Used to convert absolute wire indices to local
    /// prev_entries positions for hardlink back-references.
    pub ndx_start: i32,
}

/// Update delta state after encoding/decoding an entry.
pub fn update_delta_state(state: &mut DeltaState, entry: &FileEntry) {
    state.prev_name.clone_from(&entry.name);
    state.prev_mtime = entry.mtime;
    state.prev_mode = entry.mode;
    state.prev_uid = entry.uid;
    state.prev_gid = entry.gid;
    state.prev_rdev = entry.rdev;
    state.prev_rdev_major = entry.rdev_major();
    state.prev_user_name.clone_from(&entry.user_name);
    state.prev_group_name.clone_from(&entry.group_name);
}
