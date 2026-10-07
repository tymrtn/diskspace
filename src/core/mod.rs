pub mod airlock_store;
pub mod autonomy;
pub mod bundle;
pub mod candidate;
pub mod classify;
pub mod cloud;
pub mod fsutil;
pub mod grant;
pub mod history;
pub mod metrics;
pub mod provenance;
pub mod repack;
pub mod rules;
pub mod safety;
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

/// RAII guard: swap `$HOME` to `new_home` for a test while holding
/// [`HOME_TEST_LOCK`], restore on drop.
#[cfg(test)]
pub(crate) struct HomeGuard {
    prior: Option<String>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl HomeGuard {
    pub(crate) fn set(new_home: &std::path::Path) -> Self {
        // Poisoning is fine — the lock only guards a unit `()`; recover it.
        let lock = HOME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prior = std::env::var("HOME").ok();
        std::env::set_var("HOME", new_home);
        Self { prior, _lock: lock }
    }
}

/// Test fixtures are written moments before the gate runs, and the pressure
/// test's liveness step refuses files modified in the last 24h. Backdate every
/// file under `root` so a fixture looks like a cache nobody touched this week.
#[cfg(test)]
pub(crate) fn backdate_files(root: &std::path::Path) {
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3 * 24 * 3600);
    for entry in std::fs::read_dir(root).unwrap().flatten() {
        let p = entry.path();
        if p.is_dir() {
            backdate_files(&p);
        } else {
            std::fs::File::options()
                .write(true)
                .open(&p)
                .unwrap()
                .set_modified(old)
                .unwrap();
        }
    }
}

#[cfg(test)]
impl Drop for HomeGuard {
    fn drop(&mut self) {
        match &self.prior {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
    }
}
