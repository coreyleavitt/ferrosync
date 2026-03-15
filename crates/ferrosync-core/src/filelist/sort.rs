//! Canonical sort order for rsync file lists.
//!
//! Rsync requires file entries to be sorted in a specific order that treats
//! directories as if they have a trailing `/` separator. This ensures that
//! at any given directory level, regular files sort before subdirectories.

use super::entry::{FileEntry, S_IFDIR, S_IFMT};

/// Sort a file list in rsync's canonical order.
///
/// The sort is stable and matches rsync's `f_name_cmp` behavior for
/// protocol >= 29 (directories sort after non-directories at the same level).
pub fn canonical_sort(entries: &mut [FileEntry]) {
    entries.sort_by(f_name_cmp);
}

/// Compare two file entries in rsync's canonical order.
///
/// The comparison walks through the path components of each entry,
/// treating directories as if they end with `/`. At any given directory
/// level, regular files sort before subdirectories.
///
/// This matches rsync's `f_name_cmp` for protocol >= 29.
pub fn f_name_cmp(a: &FileEntry, b: &FileEntry) -> std::cmp::Ordering {
    // This is a faithful port of rsync's f_name_cmp from flist.c.
    //
    // Each entry's virtual path is walked as a sequence of characters:
    //   dirname + "/" + basename + (if dir: "/")
    //
    // The comparison uses a "type" (t_PATH vs t_ITEM) that dynamically
    // changes as we transition through path components. t_PATH entries
    // sort after t_ITEM entries, which ensures directories sort after
    // files at each level.

    #[derive(Clone, Copy, PartialEq)]
    enum State {
        Dir,      // Walking through dirname bytes
        Slash,    // The "/" between dirname and basename
        Base,     // Walking through basename bytes
        Trailing, // The implicit trailing "/" for directories
        Done,     // Past the end
    }

    /// Whether this entry is a "path" type (directory being descended into).
    #[derive(Clone, Copy, PartialEq)]
    enum FncType {
        Path, // Directories (with subdirectories or dirname)
        Item, // Regular files, "." root dir
    }

    struct Walker<'a> {
        basename: &'a [u8],
        dirname: Option<&'a [u8]>,
        is_dir: bool,
        state: State,
        fnc_type: FncType,
        pos: usize,
    }

    impl<'a> Walker<'a> {
        fn new(entry: &'a FileEntry) -> Self {
            let dirname = entry.dirname();
            let basename = entry.basename();
            let is_dir = (entry.mode & S_IFMT) == S_IFDIR;

            if let Some(d) = dirname {
                // Has dirname -> start walking dirname, type = PATH
                let (state, pos) = if d.is_empty() {
                    (State::Slash, 0)
                } else {
                    (State::Dir, 0)
                };
                Walker {
                    basename,
                    dirname,
                    is_dir,
                    state,
                    fnc_type: FncType::Path,
                    pos,
                }
            } else {
                // No dirname
                let fnc_type = if is_dir { FncType::Path } else { FncType::Item };
                if is_dir && basename == b"." {
                    // Special: "." root dir is t_ITEM, starts at trailing
                    Walker {
                        basename,
                        dirname: None,
                        is_dir,
                        state: State::Trailing,
                        fnc_type: FncType::Item,
                        pos: 0,
                    }
                } else {
                    Walker {
                        basename,
                        dirname: None,
                        is_dir,
                        state: State::Base,
                        fnc_type,
                        pos: 0,
                    }
                }
            }
        }

        /// Get current character, advancing state when at end of segment.
        /// Returns None only when truly done.
        fn current_char(&mut self) -> Option<u8> {
            loop {
                match self.state {
                    State::Dir => {
                        let d = self.dirname.unwrap();
                        if self.pos < d.len() {
                            return Some(d[self.pos]);
                        }
                        // End of dirname -> transition to slash
                        self.state = State::Slash;
                        self.pos = 0;
                    }
                    State::Slash => {
                        return Some(b'/');
                    }
                    State::Base => {
                        if self.pos < self.basename.len() {
                            return Some(self.basename[self.pos]);
                        }
                        // End of basename -> transition to trailing (dir) or done
                        self.state = State::Trailing;
                        if self.fnc_type == FncType::Path {
                            // Directory: emit trailing "/"
                            return Some(b'/');
                        }
                        // File: fall through to trailing -> done
                        self.fnc_type = FncType::Item;
                    }
                    State::Trailing => {
                        self.fnc_type = FncType::Item;
                        self.state = State::Done;
                        return None;
                    }
                    State::Done => {
                        return None;
                    }
                }
            }
        }

        /// Advance past the current character.
        fn advance(&mut self) {
            match self.state {
                State::Dir => {
                    self.pos += 1;
                }
                State::Slash => {
                    // After the slash, update type based on whether entry is dir.
                    self.fnc_type = if self.is_dir {
                        FncType::Path
                    } else {
                        FncType::Item
                    };
                    // Special case: basename is "." for a dir
                    if self.fnc_type == FncType::Path
                        && self.basename.len() == 1
                        && self.basename[0] == b'.'
                    {
                        self.fnc_type = FncType::Item;
                        self.state = State::Trailing;
                    } else {
                        self.state = State::Base;
                    }
                    self.pos = 0;
                }
                State::Base => {
                    self.pos += 1;
                }
                State::Trailing => {
                    self.fnc_type = FncType::Item;
                    self.state = State::Done;
                    self.pos = 0;
                }
                State::Done => {}
            }
        }
    }

    let mut wa = Walker::new(a);
    let mut wb = Walker::new(b);

    // Initial type check (matches rsync lines 3264-3265)
    if wa.fnc_type != wb.fnc_type {
        return if wa.fnc_type == FncType::Path {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Less
        };
    }

    loop {
        let ca = wa.current_char();
        let cb = wb.current_char();

        match (ca, cb) {
            (None, None) => return std::cmp::Ordering::Equal,
            (None, Some(_)) => {
                // a is done but b continues
                // After a's state transition, check type mismatch
                if wa.fnc_type != wb.fnc_type {
                    return if wa.fnc_type == FncType::Path {
                        std::cmp::Ordering::Greater
                    } else {
                        std::cmp::Ordering::Less
                    };
                }
                return std::cmp::Ordering::Less;
            }
            (Some(_), None) => {
                // b is done but a continues
                if wa.fnc_type != wb.fnc_type {
                    return if wa.fnc_type == FncType::Path {
                        std::cmp::Ordering::Greater
                    } else {
                        std::cmp::Ordering::Less
                    };
                }
                return std::cmp::Ordering::Greater;
            }
            (Some(ac), Some(bc)) => {
                if ac != bc {
                    return ac.cmp(&bc);
                }
                wa.advance();
                wb.advance();

                // After advancing past a shared character, check if types
                // have diverged (e.g., one transitioned from slash to path
                // and the other to item).
                if wa.fnc_type != wb.fnc_type {
                    // Only apply type comparison if at least one side has
                    // more characters remaining.
                    let a_has_more = wa.current_char().is_some();
                    let b_has_more = wb.current_char().is_some();
                    if a_has_more || b_has_more {
                        return if wa.fnc_type == FncType::Path {
                            std::cmp::Ordering::Greater
                        } else {
                            std::cmp::Ordering::Less
                        };
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filelist::entry::{S_IFDIR, S_IFREG};

    fn file_entry(name: &[u8], is_dir: bool) -> FileEntry {
        FileEntry {
            name: name.to_vec(),
            mode: if is_dir {
                S_IFDIR | 0o755
            } else {
                S_IFREG | 0o644
            },
            ..Default::default()
        }
    }

    #[test]
    fn test_simple_sort() {
        let mut entries = vec![
            file_entry(b"c.txt", false),
            file_entry(b"a.txt", false),
            file_entry(b"b.txt", false),
        ];
        canonical_sort(&mut entries);
        assert_eq!(entries[0].name, b"a.txt");
        assert_eq!(entries[1].name, b"b.txt");
        assert_eq!(entries[2].name, b"c.txt");
    }

    #[test]
    fn test_files_before_dirs_at_same_level() {
        let mut entries = vec![
            file_entry(b"subdir", true),
            file_entry(b"aaa.txt", false),
            file_entry(b"zzz.txt", false),
        ];
        canonical_sort(&mut entries);
        // Files (t_ITEM) sort before directories (t_PATH) at root level,
        // matching rsync's f_name_cmp behavior.
        assert_eq!(entries[0].name, b"aaa.txt");
        assert_eq!(entries[1].name, b"zzz.txt");
        assert_eq!(entries[2].name, b"subdir");
    }

    #[test]
    fn test_nested_paths() {
        let mut entries = vec![
            file_entry(b"src/main.rs", false),
            file_entry(b"src/lib.rs", false),
            file_entry(b"README.md", false),
            file_entry(b"src", true),
        ];
        canonical_sort(&mut entries);
        // README.md (root-level file, t_ITEM) sorts first,
        // then src/ (root-level dir, t_PATH),
        // then src/* entries (also t_PATH with dirname).
        assert_eq!(entries[0].name, b"README.md");
        assert_eq!(entries[1].name, b"src");
        assert_eq!(entries[2].name, b"src/lib.rs");
        assert_eq!(entries[3].name, b"src/main.rs");
    }

    #[test]
    fn test_same_names() {
        let a = file_entry(b"foo", false);
        let b = file_entry(b"foo", false);
        assert_eq!(f_name_cmp(&a, &b), std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_dir_trailing_slash_effect() {
        // Root-level directories (t_PATH) sort after root-level files (t_ITEM)
        // in rsync's f_name_cmp for proto >= 29.
        let dir = file_entry(b"abc", true);
        let file_abcd = file_entry(b"abcd", false);
        let file_abd = file_entry(b"abd", false);

        // "abc" (dir, t_PATH) vs "abcd" (file, t_ITEM): dir sorts after file
        assert_eq!(f_name_cmp(&dir, &file_abcd), std::cmp::Ordering::Greater);
        // "abc" (dir, t_PATH) vs "abd" (file, t_ITEM): dir sorts after file
        assert_eq!(f_name_cmp(&dir, &file_abd), std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_sort_stability_with_subdirs() {
        let mut entries = vec![
            file_entry(b"z", false),
            file_entry(b"a/b", false),
            file_entry(b"a", true),
            file_entry(b"a/a", false),
            file_entry(b"m", false),
        ];
        canonical_sort(&mut entries);

        // Root-level files (t_ITEM) sort before root-level dirs (t_PATH).
        // Within the same type, normal alphabetical comparison applies.
        let names: Vec<&[u8]> = entries.iter().map(|e| e.name.as_slice()).collect();
        assert_eq!(names, vec![&b"m"[..], b"z", b"a", b"a/a", b"a/b"]);
    }
}
