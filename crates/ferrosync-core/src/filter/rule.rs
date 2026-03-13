//! Filter rule types and rule list evaluation.

use crate::error::FilterError;

use super::pattern::Pattern;

/// Action to take when a filter rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterAction {
    /// Include the file in the transfer.
    Include,
    /// Exclude the file from the transfer.
    Exclude,
}

/// A single filter rule: an action paired with a pattern.
#[derive(Debug, Clone)]
pub struct FilterRule {
    pub action: FilterAction,
    pub pattern: Pattern,
}

impl FilterRule {
    /// Parse a filter rule from a string.
    ///
    /// Accepted formats:
    /// - `- pattern` (exclude)
    /// - `+ pattern` (include)
    /// - `exclude pattern` / `include pattern`
    pub fn parse(s: &str) -> Result<Self, FilterError> {
        let s = s.trim();

        let (action, pattern_str) = if let Some(rest) = s.strip_prefix("- ") {
            (FilterAction::Exclude, rest.trim())
        } else if let Some(rest) = s.strip_prefix("+ ") {
            (FilterAction::Include, rest.trim())
        } else if let Some(rest) = s.strip_prefix("exclude ") {
            (FilterAction::Exclude, rest.trim())
        } else if let Some(rest) = s.strip_prefix("include ") {
            (FilterAction::Include, rest.trim())
        } else {
            return Err(FilterError::InvalidRule {
                rule: s.to_string(),
            });
        };

        let pattern = Pattern::new(pattern_str)?;
        Ok(Self { action, pattern })
    }

    /// Test whether this rule matches a given path.
    pub fn matches(&self, path: &[u8], is_dir: bool) -> bool {
        self.pattern.matches(path, is_dir)
    }
}

/// An ordered list of filter rules.
///
/// Rules are evaluated in order; the first matching rule determines the
/// outcome. If no rule matches, the file is included (default include).
#[derive(Debug, Clone, Default)]
pub struct FilterRuleList {
    rules: Vec<FilterRule>,
}

impl FilterRuleList {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add an exclude pattern (from `--exclude`).
    pub fn add_exclude(&mut self, pattern: &str) -> Result<(), FilterError> {
        self.rules.push(FilterRule {
            action: FilterAction::Exclude,
            pattern: Pattern::new(pattern)?,
        });
        Ok(())
    }

    /// Add an include pattern (from `--include`).
    pub fn add_include(&mut self, pattern: &str) -> Result<(), FilterError> {
        self.rules.push(FilterRule {
            action: FilterAction::Include,
            pattern: Pattern::new(pattern)?,
        });
        Ok(())
    }

    /// Add a filter rule string (from `--filter` / `-f`).
    pub fn add_rule(&mut self, rule: &str) -> Result<(), FilterError> {
        self.rules.push(FilterRule::parse(rule)?);
        Ok(())
    }

    /// Build a filter rule list from [`TransferOptions`] exclude/include/filter lists.
    pub fn from_options(
        excludes: &[String],
        includes: &[String],
        filters: &[String],
    ) -> Result<Self, FilterError> {
        let mut list = Self::new();

        // Filter rules are added first (they have highest priority in rsync).
        for f in filters {
            list.add_rule(f)?;
        }
        // Then includes.
        for i in includes {
            list.add_include(i)?;
        }
        // Then excludes.
        for e in excludes {
            list.add_exclude(e)?;
        }

        Ok(list)
    }

    /// Check whether a path should be included in the transfer.
    ///
    /// Returns `true` if included, `false` if excluded.
    pub fn is_included(&self, path: &[u8], is_dir: bool) -> bool {
        for rule in &self.rules {
            if rule.matches(path, is_dir) {
                return rule.action == FilterAction::Include;
            }
        }
        // Default: include.
        true
    }

    /// Number of rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether the rule list is empty.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_exclude() {
        let rule = FilterRule::parse("- *.tmp").unwrap();
        assert_eq!(rule.action, FilterAction::Exclude);
        assert!(rule.matches(b"foo.tmp", false));
    }

    #[test]
    fn test_parse_include() {
        let rule = FilterRule::parse("+ *.rs").unwrap();
        assert_eq!(rule.action, FilterAction::Include);
        assert!(rule.matches(b"main.rs", false));
    }

    #[test]
    fn test_parse_long_form() {
        let rule = FilterRule::parse("exclude *.log").unwrap();
        assert_eq!(rule.action, FilterAction::Exclude);

        let rule = FilterRule::parse("include *.txt").unwrap();
        assert_eq!(rule.action, FilterAction::Include);
    }

    #[test]
    fn test_parse_invalid() {
        assert!(FilterRule::parse("bad rule").is_err());
    }

    #[test]
    fn test_rule_list_exclude() {
        let mut list = FilterRuleList::new();
        list.add_exclude("*.tmp").unwrap();
        list.add_exclude("*.log").unwrap();

        assert!(!list.is_included(b"foo.tmp", false));
        assert!(!list.is_included(b"bar.log", false));
        assert!(list.is_included(b"main.rs", false));
    }

    #[test]
    fn test_rule_list_include_before_exclude() {
        let mut list = FilterRuleList::new();
        list.add_include("important.log").unwrap();
        list.add_exclude("*.log").unwrap();

        assert!(list.is_included(b"important.log", false));
        assert!(!list.is_included(b"debug.log", false));
    }

    #[test]
    fn test_rule_list_default_include() {
        let list = FilterRuleList::new();
        assert!(list.is_included(b"anything", false));
        assert!(list.is_included(b"any/path/at/all", true));
    }

    #[test]
    fn test_from_options() {
        let excludes = vec!["*.tmp".to_string(), "*.bak".to_string()];
        let includes = vec!["important.tmp".to_string()];
        let filters = vec![];

        let list = FilterRuleList::from_options(&excludes, &includes, &filters).unwrap();
        assert_eq!(list.len(), 3);

        // include rule comes before exclude, so important.tmp is included.
        assert!(list.is_included(b"important.tmp", false));
        assert!(!list.is_included(b"other.tmp", false));
    }

    #[test]
    fn test_filter_rules_priority() {
        let filters = vec!["- *.secret".to_string()];
        let includes = vec!["*.secret".to_string()];
        let excludes = vec![];

        let list = FilterRuleList::from_options(&excludes, &includes, &filters).unwrap();

        // Filter rule comes first, overrides the include.
        assert!(!list.is_included(b"password.secret", false));
    }

    #[test]
    fn test_dir_only_filter() {
        let mut list = FilterRuleList::new();
        list.add_exclude("build/").unwrap();

        assert!(!list.is_included(b"build", true));
        assert!(list.is_included(b"build", false)); // file named "build" is ok
    }
}
