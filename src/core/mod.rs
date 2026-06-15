pub mod airlock_store;
pub mod bundle;
pub mod candidate;
pub mod fsutil;
pub mod grant;
pub mod history;
pub mod metrics;
pub mod rules;
pub mod scanner;
pub mod series;

/// Crate-wide, test-only `$HOME` serialization lock.
///
/// `$HOME` is process-global and several test modules (`commands::doctor`,
/// `commands::watch`, `commands::selfcheck`) override it so that
/// `profile::data_dir()` resolves under a tempdir. Cargo runs tests in parallel
/// THREADS within ONE process, so independent per-module `Mutex`es do NOT
/// serialize against each other — two modules could flip `$HOME` concurrently
/// and corrupt each other's stores. Every test that mutates `$HOME` MUST hold
/// THIS single shared lock for the duration of the override.
#[cfg(test)]
pub(crate) static HOME_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
