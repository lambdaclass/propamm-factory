//! Tasks that must not outlive the scope that spawned them.
//!
//! When `run` owned the whole process, its tasks died with the runtime `run_from_env`
//! dropped. Inside a caller's runtime they would keep going after `run` returned: a head
//! watcher polling an RPC nobody reads, an exporter holding its port, a watchdog printing
//! notices for a service that is gone. Every long-lived task `run` starts goes through a
//! `Tasks`, which aborts them all when it drops, on every way out of `run`, error paths
//! included.

use std::future::Future;

use tokio::task::{AbortHandle, JoinHandle};

/// Spawns tasks and aborts all of them on drop.
#[derive(Default)]
pub(crate) struct Tasks(Vec<AbortHandle>);

impl Tasks {
    /// `tokio::spawn`, remembered for abort.
    pub(crate) fn spawn<F>(&mut self, fut: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let handle = tokio::spawn(fut);
        self.0.push(handle.abort_handle());
        handle
    }

    /// Takes on a task something else spawned (the exporter, the backoffice).
    pub(crate) fn adopt<T>(&mut self, handle: &JoinHandle<T>) {
        self.0.push(handle.abort_handle());
    }
}

impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dropping_the_group_aborts_what_it_spawned() {
        let mut tasks = Tasks::default();
        let handle = tasks.spawn(std::future::pending::<()>());
        drop(tasks);
        let err = handle.await.expect_err("an aborted task does not complete");
        assert!(err.is_cancelled());
    }
}
