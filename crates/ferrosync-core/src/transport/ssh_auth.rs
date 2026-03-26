//! SSH authentication callback traits.
//!
//! The SSH transport is a library component that must not hardcode UI decisions.
//! When authentication requires user interaction (password entry, keyboard-interactive
//! prompts), the transport calls through [`AuthPrompter`]. The CLI provides a
//! `/dev/tty`-based implementation; tests use mocks.

use std::future::Future;
use std::pin::Pin;

/// Callback trait for interactive SSH authentication.
///
/// Implementations handle the user-facing side of password and keyboard-interactive
/// auth. The transport layer calls these methods when the server requests credentials
/// that cannot be satisfied by agent or key-based auth alone.
///
/// This trait is dyn-compatible so it can be stored as `Arc<dyn AuthPrompter>` in
/// transport config.
pub trait AuthPrompter: Send + Sync {
    /// Prompt the user for a password.
    ///
    /// Called when the server accepts password authentication and no prior method
    /// succeeded. Returns `None` if the user cancels (e.g., Ctrl-C / EOF).
    fn prompt_password(
        &self,
        user: &str,
        host: &str,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>>;

    /// Handle a keyboard-interactive authentication round.
    ///
    /// `name` and `instructions` come from the server (may be empty strings).
    /// `prompts` contains `(prompt_text, echo)` pairs -- when `echo` is false,
    /// the implementation should suppress input display (like a password prompt).
    ///
    /// Returns responses in the same order as `prompts`, or `None` if the user
    /// cancels.
    fn prompt_keyboard_interactive(
        &self,
        user: &str,
        host: &str,
        name: &str,
        instructions: &str,
        prompts: &[(String, bool)],
    ) -> Pin<Box<dyn Future<Output = Option<Vec<String>>> + Send + '_>>;
}
