//! The pusher's configuration while it runs, shared by the backoffice API, an
//! `UpdaterHandle` and the service that quotes it.
//!
//! Read from the config file once, at boot. From then on it changes only through
//! [`Editing::change`], which applies the change to a copy, writes the copy to the file,
//! has the service converge the running pairs onto it, and keeps it only if the service
//! accepts: so the shared config always says what is running, and the file always holds
//! it for the next boot.
//!
//! The file's `target` and `[settings]` are the exception. Each is read once, at boot, and
//! changed only by editing the file and restarting, so a write keeps whatever the file says
//! for them, a hand edit waiting for that restart included, while the shared config keeps
//! the ones the pusher is running. A hand edit of the pairs or builders is read at the next
//! start too, but the next change made here overwrites it.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use tokio::sync::{Mutex, MutexGuard, mpsc, oneshot};

use crate::{config::RawConfig, service::ReloadFailure};

/// A request for the service to converge the running pairs onto `config`, and to say how
/// that went. Every one carries the config whole, so the service never reads one of its
/// own: what it converges onto is exactly what the asker will keep or drop.
pub(crate) struct ReloadRequest {
    pub(crate) config: Arc<RawConfig>,
    pub(crate) reply: oneshot::Sender<Result<String, ReloadFailure>>,
}

/// The config every part of a run reads and the one place it is changed.
pub(crate) struct SharedConfig {
    /// The file read at boot and written on every change.
    path: PathBuf,
    /// What the service last converged onto. Behind a std lock held for a clone of the
    /// `Arc` only, so a reader never waits out a converge.
    current: RwLock<Arc<RawConfig>>,
    /// Serializes changes. Two at once would each copy the config and the second would
    /// drop the first's change; it also covers a plain reload, so one cannot converge onto
    /// a config a change is about to replace.
    edits: Mutex<()>,
    /// The service's request channel.
    reloads: mpsc::Sender<ReloadRequest>,
}

/// Why a change was not kept whole.
#[derive(Debug)]
pub(crate) enum Refused<E> {
    /// The change itself refused, before anything was written or converged: a pair that is
    /// not there, a name already taken. Its own type, so each caller says it its own way.
    Change(E),
    /// The service's verdict, or a file that could not be written. A
    /// [`ReloadFailure::Partial`] change is kept, in the file and in the shared config.
    Reload(ReloadFailure),
}

impl SharedConfig {
    /// The config as read at boot.
    pub(crate) fn new(
        path: PathBuf,
        config: RawConfig,
        reloads: mpsc::Sender<ReloadRequest>,
    ) -> Self {
        Self {
            path,
            current: RwLock::new(Arc::new(config)),
            edits: Mutex::new(()),
            reloads,
        }
    }

    /// The file this config was read from and is written back to.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// The config as it is now. Never waits for a change in flight: it answers with the
    /// config from before it until the service has accepted it.
    pub(crate) fn snapshot(&self) -> Arc<RawConfig> {
        // A poisoned lock still holds a whole `Arc`: nothing is ever left half-written.
        Arc::clone(&self.current.read().unwrap_or_else(|p| p.into_inner()))
    }

    /// Waits for any change in flight and holds off the next, so a caller can look at the
    /// config and change it as one step.
    pub(crate) async fn edit(&self) -> Editing<'_> {
        Editing {
            shared: self,
            _guard: self.edits.lock().await,
        }
    }

    /// [`Editing::change`], on its own.
    pub(crate) async fn change<E>(
        &self,
        by: &str,
        change: impl FnOnce(&mut RawConfig) -> Result<String, E>,
    ) -> Result<String, Refused<E>> {
        self.edit().await.change(by, change).await
    }

    /// [`Editing::reload`], on its own.
    pub(crate) async fn reload(&self) -> Result<String, ReloadFailure> {
        self.edit().await.reload().await
    }

    fn commit(&self, config: Arc<RawConfig>) {
        *self.current.write().unwrap_or_else(|p| p.into_inner()) = config;
    }
}

/// The right to change the shared config, held until dropped. See [`SharedConfig::edit`].
pub(crate) struct Editing<'a> {
    shared: &'a SharedConfig,
    _guard: MutexGuard<'a, ()>,
}

impl Editing<'_> {
    /// The config as it is now; nothing else can change it while this is held.
    pub(crate) fn config(&self) -> Arc<RawConfig> {
        self.shared.snapshot()
    }

    /// Applies `change` to a copy of the config, writes the copy to the file (with the
    /// file's own `target` and `[settings]`: see the module's doc), and asks the service to
    /// converge onto it. `change` answers with what it did, for the line; `by` names the
    /// asker in the journal.
    ///
    /// `Ok` is a change live on every pair. [`ReloadFailure::Partial`] is one live on every
    /// pair the converge reached, kept in the file and the shared config, since putting it
    /// back would describe neither what runs nor what was asked for.
    /// [`ReloadFailure::Rejected`] leaves both as they were: the file is put back (or, if it
    /// could not be, the line says so), and the shared config was never changed.
    pub(crate) async fn change<E>(
        &mut self,
        by: &str,
        change: impl FnOnce(&mut RawConfig) -> Result<String, E>,
    ) -> Result<String, Refused<E>> {
        let shared = self.shared;
        let mut candidate = RawConfig::clone(&shared.snapshot());
        let what = change(&mut candidate).map_err(Refused::Change)?;
        let rejected = |line: String| Refused::Reload(ReloadFailure::Rejected(line));

        // Written before the service sees it, so the file is never behind what runs, and a
        // file that cannot be written refuses the change before anything moves. The bytes
        // it replaces are kept, so a rejection puts them back exactly, comments and all.
        let before = std::fs::read(&shared.path).ok();
        let (written, note) = with_file_settings(&candidate, before.as_deref(), &shared.path);
        if let Some(note) = &note {
            tracing::warn!("{by} {what}: {note}");
        }
        crate::config::write_raw_atomically(&shared.path, &written)
            .map_err(|err| rejected(format!("{what} was not made: {err:#}")))?;
        let note = note
            .map(|note| format!(" Note: {note}."))
            .unwrap_or_default();

        let candidate = Arc::new(candidate);
        match converge(&shared.reloads, Arc::clone(&candidate)).await {
            Ok(summary) => {
                shared.commit(candidate);
                tracing::info!("{by} {what}; {summary}");
                Ok(format!("{what}. {summary}{note}"))
            }
            // Kept: the converge stopped, started and restarted what it could, so the new
            // config already describes those lanes, and dropping it would have the next
            // reload undo them (a halt, say, lifted by an unrelated change).
            Err(ReloadFailure::Partial(summary)) => {
                shared.commit(candidate);
                tracing::warn!("{by} {what}; applied in part, the change is kept: {summary}");
                Err(Refused::Reload(ReloadFailure::Partial(format!(
                    "{what}, but the reload applied in part: {summary}. The change is kept, \
                     live on every pair the reload reached; the next reload retries the \
                     rest.{note}"
                ))))
            }
            Err(ReloadFailure::Rejected(err)) => {
                // Put back before the rejection is reported, so by the time it is read the
                // file already matches what is running again.
                let restored = match &before {
                    Some(bytes) => std::fs::write(&shared.path, bytes).map_err(|e| e.to_string()),
                    None => crate::config::write_raw_atomically(&shared.path, &shared.snapshot())
                        .map_err(|e| format!("{e:#}")),
                };
                tracing::warn!("{by} {what} REJECTED, nothing changed: {err}");
                Err(rejected(match restored {
                    Ok(()) => format!("{what} was rejected and nothing changed: {err}"),
                    Err(write_err) => format!(
                        "{what} was rejected ({err}) and nothing changed, but the config file \
                         could not be put back ({write_err}): {} now holds the rejected change, \
                         which the next start would load. Fix it before then.",
                        shared.path.display()
                    ),
                }))
            }
        }
    }

    /// Converges the running pairs onto the config as it is, changing nothing in it: the
    /// way a lane its circuit breaker halted is brought back, and one whose feed never came
    /// up is tried again.
    pub(crate) async fn reload(&mut self) -> Result<String, ReloadFailure> {
        converge(&self.shared.reloads, self.config()).await
    }
}

/// What a change writes to the file: `candidate`, with the `target` and `[settings]` the
/// file holds now (`on_disk`), since those are the file's to change and not the API's. A
/// file that is gone or does not parse has none to keep: the candidate's are written, and
/// the note says what that may have overwritten.
fn with_file_settings(
    candidate: &RawConfig,
    on_disk: Option<&[u8]>,
    path: &Path,
) -> (RawConfig, Option<String>) {
    let mut written = candidate.clone();
    let Some(bytes) = on_disk else {
        return (written, None);
    };
    let parsed = std::str::from_utf8(bytes)
        .map_err(|err| eyre::eyre!("{err}"))
        .and_then(crate::config::parse_raw);
    match parsed {
        Ok(file) => {
            written.target = file.target;
            written.settings = file.settings;
            (written, None)
        }
        Err(err) => (
            written,
            Some(format!(
                "{} did not parse ({err:#}), so it was rewritten whole from the running \
                 config, a hand edit in it included",
                path.display()
            )),
        ),
    }
}

/// Asks the service to converge onto `config` and waits for its verdict. A service that is
/// gone, or went before it answered, counts as a rejection: nothing says it applied anything.
async fn converge(
    reloads: &mpsc::Sender<ReloadRequest>,
    config: Arc<RawConfig>,
) -> Result<String, ReloadFailure> {
    let (reply, answer) = oneshot::channel();
    reloads
        .send(ReloadRequest { config, reply })
        .await
        .map_err(|_| {
            ReloadFailure::Rejected(
                "the pusher has stopped, or is stopping, and is not reloading".to_owned(),
            )
        })?;
    answer.await.map_err(|_| {
        ReloadFailure::Rejected("the pusher has stopped before it answered the reload".to_owned())
    })?
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn a_config() -> RawConfig {
        crate::config::parse_raw(
            r#"
target = "0x1111111111111111111111111111111111111111"

[[pairs]]
tokens  = ["0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
           "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"]
symbol  = "ETHUSDC"
key_env = "UPDATER_KEY_WETH_USDC"
pricing = { kind = "feed" }

[[builder]]
name = "titan-eu"
endpoint = "wss://eu.example/ws"
api_key = "k"
"#,
        )
        .unwrap()
    }

    /// A shared config over a file in a fresh directory, holding `a_config` as written by
    /// hand (comments and all), and the service end of its channel.
    pub(crate) fn on_disk(name: &str) -> (Arc<SharedConfig>, mpsc::Receiver<ReloadRequest>) {
        let dir =
            std::env::temp_dir().join(format!("quote-updater-state-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let text = format!(
            "# written by hand\n{}",
            crate::config::render_raw(&a_config()).unwrap()
        );
        std::fs::write(&path, text).unwrap();
        let (tx, rx) = mpsc::channel(1);
        let config = crate::config::load_raw(&path).unwrap();
        (Arc::new(SharedConfig::new(path, config, tx)), rx)
    }

    /// Answers the next request with `verdict`, and hands back the config it was asked to
    /// converge onto.
    fn service(
        mut requests: mpsc::Receiver<ReloadRequest>,
        verdict: Result<String, ReloadFailure>,
    ) -> tokio::task::JoinHandle<Arc<RawConfig>> {
        tokio::spawn(async move {
            let request = requests.recv().await.expect("a reload must be requested");
            let _ = request.reply.send(verdict);
            request.config
        })
    }

    fn set_deviation(config: &mut RawConfig) -> Result<String, eyre::Report> {
        config.pairs[0].max_deviation = Some("0.02".to_owned());
        Ok("edited pair UPDATER_KEY_WETH_USDC".to_owned())
    }

    /// The property everything rests on: a refused change leaves the file exactly as it
    /// was, and the shared config as it was, so both still describe what is running.
    #[tokio::test]
    async fn a_rejected_change_leaves_the_file_and_the_config_as_they_were() {
        let (shared, requests) = on_disk("reject");
        let before = std::fs::read_to_string(shared.path()).unwrap();
        let service = service(
            requests,
            Err(ReloadFailure::Rejected("preflight failed".to_owned())),
        );

        let err = shared.change("test:", set_deviation).await.unwrap_err();
        let asked = service.await.unwrap();

        assert_eq!(asked.pairs[0].max_deviation.as_deref(), Some("0.02"));
        let Refused::Reload(ReloadFailure::Rejected(line)) = err else {
            panic!("{err:?}")
        };
        assert!(line.contains("nothing changed"), "{line}");
        assert_eq!(
            std::fs::read_to_string(shared.path()).unwrap(),
            before,
            "the file must be byte-identical to what it was before the rejected change"
        );
        assert_eq!(shared.snapshot().pairs[0].max_deviation, None);
    }

    /// A converge that applied in part (another pair's feed would not come up) keeps the
    /// change, in the file and in the shared config, and says it is not a clean success.
    #[tokio::test]
    async fn a_partly_applied_change_is_kept_and_says_so() {
        let (shared, requests) = on_disk("partial");
        let service = service(
            requests,
            Err(ReloadFailure::Partial(
                "reload: 1 restarted, 1 failed".to_owned(),
            )),
        );

        let err = shared.change("test:", set_deviation).await.unwrap_err();
        service.await.unwrap();

        let Refused::Reload(ReloadFailure::Partial(line)) = err else {
            panic!("{err:?}")
        };
        assert!(line.contains("is kept"), "{line}");
        assert!(!line.contains("nothing changed"), "{line}");
        assert_eq!(
            shared.snapshot().pairs[0].max_deviation.as_deref(),
            Some("0.02")
        );
        let written = crate::config::load_raw(shared.path()).unwrap();
        assert_eq!(written.pairs[0].max_deviation.as_deref(), Some("0.02"));
    }

    /// And an accepted one is kept, in the shared config and in the file, at 0600 and
    /// loadable by the real parser.
    #[tokio::test]
    async fn an_accepted_change_is_kept_in_the_config_and_the_file() {
        let (shared, requests) = on_disk("accept");
        let service = service(requests, Ok("reload: 1 restarted".to_owned()));

        let line = shared.change("test:", set_deviation).await.unwrap();
        service.await.unwrap();

        assert_eq!(
            line,
            "edited pair UPDATER_KEY_WETH_USDC. reload: 1 restarted"
        );
        assert_eq!(
            shared.snapshot().pairs[0].max_deviation.as_deref(),
            Some("0.02")
        );
        let written = crate::config::load_raw(shared.path()).unwrap();
        assert_eq!(written.pairs[0].max_deviation.as_deref(), Some("0.02"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(shared.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "the config holds builder API keys");
        }
    }

    /// A change the closure refuses touches nothing and asks the service nothing.
    #[tokio::test]
    async fn a_refused_change_writes_nothing_and_converges_nothing() {
        let (shared, mut requests) = on_disk("refused");
        let before = std::fs::read_to_string(shared.path()).unwrap();

        let err = shared
            .change("test:", |_| Err::<String, _>("no such pair"))
            .await
            .unwrap_err();

        assert!(matches!(err, Refused::Change("no such pair")), "{err:?}");
        assert_eq!(std::fs::read_to_string(shared.path()).unwrap(), before);
        assert!(
            requests.try_recv().is_err(),
            "nothing was asked of the service"
        );
    }

    /// A plain reload converges onto the config as it is and writes nothing.
    #[tokio::test]
    async fn a_reload_converges_onto_the_config_as_it_is() {
        let (shared, requests) = on_disk("reload");
        let before = std::fs::read_to_string(shared.path()).unwrap();
        let service = service(requests, Ok("nothing to do".to_owned()));

        assert_eq!(shared.reload().await.unwrap(), "nothing to do");
        let asked = service.await.unwrap();

        assert!(Arc::ptr_eq(&asked, &shared.snapshot()));
        assert_eq!(std::fs::read_to_string(shared.path()).unwrap(), before);
    }

    /// A hand edit of `target` or `[settings]` waiting for a restart is kept by a change,
    /// which writes the pairs and builders only; the converge and the shared config keep
    /// the ones the pusher is running.
    #[tokio::test]
    async fn a_change_keeps_the_files_own_target_and_settings() {
        let (shared, requests) = on_disk("hand-settings");
        let mut edited = a_config();
        edited.target = "0x2222222222222222222222222222222222222222".to_owned();
        edited.settings.requote_ms = Some(25);
        std::fs::write(shared.path(), crate::config::render_raw(&edited).unwrap()).unwrap();
        let service = service(requests, Ok("reload: 1 restarted".to_owned()));

        let line = shared.change("test:", set_deviation).await.unwrap();
        let asked = service.await.unwrap();

        assert!(!line.contains("Note"), "{line}");
        let written = crate::config::load_raw(shared.path()).unwrap();
        assert_eq!(written.pairs[0].max_deviation.as_deref(), Some("0.02"));
        assert_eq!(written.target, edited.target, "the hand edit is kept");
        assert_eq!(written.settings.requote_ms, Some(25));
        for running in [&asked, &shared.snapshot()] {
            assert_eq!(running.target, a_config().target, "what runs is unchanged");
            assert_eq!(running.settings.requote_ms, None);
        }
    }

    /// A file that does not parse has no settings to keep: the change still goes through,
    /// a halt above all, and says what it overwrote.
    #[tokio::test]
    async fn a_change_over_a_file_that_does_not_parse_says_so() {
        let (shared, requests) = on_disk("hand-broken");
        std::fs::write(shared.path(), "target = \"half an edit").unwrap();
        let service = service(requests, Ok("reload: 1 restarted".to_owned()));

        let line = shared.change("test:", set_deviation).await.unwrap();
        service.await.unwrap();

        assert!(line.contains("did not parse"), "{line}");
        let written = crate::config::load_raw(shared.path()).unwrap();
        assert_eq!(written.target, a_config().target);
        assert_eq!(written.pairs[0].max_deviation.as_deref(), Some("0.02"));
    }

    /// A service that has gone is a rejection, and the file is put back.
    #[tokio::test]
    async fn a_service_that_is_gone_rejects_the_change() {
        let (shared, requests) = on_disk("gone");
        let before = std::fs::read_to_string(shared.path()).unwrap();
        drop(requests);

        let err = shared.change("test:", set_deviation).await.unwrap_err();

        assert!(
            matches!(err, Refused::Reload(ReloadFailure::Rejected(_))),
            "{err:?}"
        );
        assert_eq!(std::fs::read_to_string(shared.path()).unwrap(), before);
        assert_eq!(shared.snapshot().pairs[0].max_deviation, None);
    }
}
