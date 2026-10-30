//! The tally of the connections an agent is serving, and the end of the agent decided from it.
//!
//! Every change to the tally goes through [`Connections::change`], which wakes everything parked on
//! it: the drain, the wait for the accept loop to return, and the loop's own wait for a connection to
//! end. A change that lowers `live` or `logouts` can satisfy a parked wait's condition, and one that
//! raises them can invalidate it, so none is left to remember its own wake. `Tally` has no other way
//! in: its fields are private to this module, and only `change` takes the lock to write.

use std::sync::{Arc, Condvar, Mutex};

/// The connections this agent is serving, so that a shortage of descriptors can wait for one to end.
pub(super) struct Connections {
    tally: Mutex<Tally>,
    ended: Condvar,
    /// How long [`Connections::wait_until_only_logouts_live`] waits for connections that do not finish.
    drain_bound: std::time::Duration,
    /// Called each time the drain is about to park, with the tally locked: the lock is released by
    /// the park itself, so what this causes to happen to a connection happens after the drain is
    /// waiting. It must not take the lock. A test uses it to know that the drain is waiting. It gets
    /// the number of live connections that are not `logout` requests, as the tally has it now, so a
    /// test can tell a park that saw its change from one that did not.
    drain_parks: Box<dyn Fn(usize) + Send + Sync>,
    /// How the end went, once it is decided (see [`Connections::settle`]).
    settled: std::sync::OnceLock<Drained>,
}

/// The longest an ending agent waits for its connections to finish relaying. Each is waiting on a
/// client (to read the last output, to close), and a client may never do either; this is the failure
/// bound on that wait, never a proof that the output arrived. When it passes the agent ends anyway
/// and logs how many connections it left.
const DRAIN_BOUND: std::time::Duration = std::time::Duration::from_secs(30);

/// How [`Connections::wait_until_only_logouts_live`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Drained {
    /// Every connection but the `logout` requests finished.
    Complete,
    /// The bound passed with `still_live` connections unfinished.
    Abandoned { still_live: usize },
}

struct Tally {
    live: usize,
    /// How many connections have ever ended: a counter, so "one ended since I looked" is a
    /// comparison and not a guess at what changed.
    ended: u64,
    /// How many of the live connections are `logout` requests waiting for the others to finish.
    logouts: usize,
    /// The end is decided: the accept loop returns after the connection it is accepting, which it
    /// counts first.
    closing: bool,
    /// An accept loop holds the listener.
    listener_open: bool,
    /// Why the loop could not be woken, if it could not: nothing will make it return.
    wake_failed: Option<String>,
}

/// A live connection. Dropping it, on any exit from the handler including a panic, ends it.
pub(super) struct Live(Option<Arc<Connections>>);

impl Connections {
    pub(super) fn new() -> Arc<Self> {
        Self::with_drain_bound(DRAIN_BOUND)
    }

    pub(super) fn with_drain_bound(drain_bound: std::time::Duration) -> Arc<Self> {
        Self::with_drain(drain_bound, |_| {})
    }

    /// [`Connections::new`] that calls `parks` each time the drain is about to park.
    #[cfg(test)]
    pub(super) fn observing_drain(parks: impl Fn() + Send + Sync + 'static) -> Arc<Self> {
        Self::with_drain(DRAIN_BOUND, move |_| parks())
    }

    pub(super) fn with_drain(
        drain_bound: std::time::Duration,
        parks: impl Fn(usize) + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            drain_bound,
            drain_parks: Box::new(parks),
            tally: Mutex::new(Tally {
                live: 0,
                ended: 0,
                logouts: 0,
                closing: false,
                listener_open: false,
                wake_failed: None,
            }),
            ended: Condvar::new(),
            settled: std::sync::OnceLock::new(),
        })
    }

    /// The tally, locked, to be read (a wait takes it to park on). Writes go through [`Connections::change`].
    fn lock(&self) -> std::sync::MutexGuard<'_, Tally> {
        self.tally.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The only way to write the tally: apply `f` under the lock, then wake everything parked on it.
    fn change<R>(&self, f: impl FnOnce(&mut Tally) -> R) -> R {
        let mut tally = self.lock();
        let result = f(&mut tally);
        self.ended.notify_all();
        result
    }

    /// How long the drain waits for connections that do not finish.
    pub(super) fn drain_bound(&self) -> std::time::Duration {
        self.drain_bound
    }

    /// Whether an accept loop holds the listener.
    #[cfg(test)]
    pub(super) fn listener_is_open(&self) -> bool {
        self.lock().listener_open
    }

    /// Wake everything parked on the tally without changing it, as a failsafe in a test does.
    #[cfg(test)]
    pub(super) fn wake(&self) {
        self.ended.notify_all();
    }

    pub(super) fn begin(self: &Arc<Self>) -> Live {
        self.change(|tally| tally.live += 1);
        Live(Some(Arc::clone(self)))
    }

    /// How many connections have ended so far.
    pub(super) fn ended(&self) -> u64 {
        self.lock().ended
    }

    /// Record that a live connection is a `logout` request. It lasts while the guard does.
    ///
    /// Wakes the drains: a connection that was live but not yet a request held them back.
    pub(super) fn begin_logout(self: &Arc<Self>) -> LogoutWait {
        self.change(|tally| tally.logouts += 1);
        LogoutWait(Arc::clone(self))
    }

    /// Return once every live connection is a `logout` request: the shells' last output has been
    /// delivered. (The end is decided by [`Connections::settle`], which calls this twice.) Each request
    /// is itself live until its handler returns, so counting them in would make two requests wait for
    /// each other for ever.
    ///
    /// A connection waits on its client, which may never act, so the wait ends after the drain bound
    /// with the connections still live. The condition is re-checked after every wake; the bound only
    /// stops the wait, it does not decide the condition.
    pub(super) fn wait_until_only_logouts_live(&self) -> Drained {
        let tally = self.lock();
        let (tally, _) = self
            .ended
            .wait_timeout_while(tally, self.drain_bound, |tally| {
                let parks = tally.live > tally.logouts;
                if parks {
                    (self.drain_parks)(tally.live - tally.logouts);
                }
                parks
            })
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let still_live = tally.live.saturating_sub(tally.logouts);
        if still_live == 0 {
            Drained::Complete
        } else {
            tracing::warn!(
                "{still_live} connection(s) had not finished {} s after the end began; ending without them",
                self.drain_bound.as_secs_f32()
            );
            Drained::Abandoned { still_live }
        }
    }

    /// An accept loop is about to run over the listener.
    pub(super) fn listener_opened(&self) {
        self.change(|tally| tally.listener_open = true);
    }

    /// The loop has returned and the listener is closed.
    pub(super) fn listener_closed(&self) {
        self.change(|tally| tally.listener_open = false);
    }

    /// Whether the end is decided: the accept loop stops after its current accept.
    pub(super) fn is_closing(&self) -> bool {
        self.lock().closing
    }

    /// The loop cannot be woken, so waiting for it would not end: the end goes on without it, and
    /// says why (see [`Connections::settle`]).
    pub(super) fn wake_failed(&self, why: &str) {
        self.change(|tally| {
            tally.wake_failed.get_or_insert_with(|| why.to_string());
        });
    }

    /// Decide the end of the agent: wait until only `logout` requests are live, stop the accept loop
    /// and close the listener, and judge again. Returns how the last judgement went. Any number of
    /// callers (the `logout` handlers, the thread that ran the loop) may ask; the first does the work
    /// and the others wait for it.
    ///
    /// The first wait is with the listener open, so a login that arrives meanwhile gets the refusal.
    /// The loop counts every connection it accepts before it looks at the flag set here, and the
    /// listener is closed once it has returned, so the second judgement sees every connection the loop
    /// took. A connection the system queued and nobody accepted is reset with the listener; its shim
    /// goes back to its no-agent path. If the first wait gave up on connections that do not finish, the
    /// second is not made: those would not finish either.
    ///
    /// `wake` makes a loop that is blocked in `accept` return from it.
    pub(super) fn settle(&self, wake: &dyn Fn()) -> Drained {
        *self.settled.get_or_init(|| {
            let first = self.wait_until_only_logouts_live();
            self.close_listener(wake);
            match first {
                Drained::Complete => self.wait_until_only_logouts_live(),
                abandoned @ Drained::Abandoned { .. } => abandoned,
            }
        })
    }

    /// Raise the flag, wake the loop and wait until it has returned and the listener is closed, or
    /// until the wake has failed. Nothing is waited for if no loop holds a listener.
    fn close_listener(&self, wake: &dyn Fn()) {
        // The change wakes a loop parked for a resource (see `wait_for_an_end`): it is not in
        // `accept`, where `wake` reaches it.
        if !self.change(|tally| {
            tally.closing = true;
            tally.listener_open
        }) {
            return;
        }
        wake();
        let tally = self.lock();
        let tally = self
            .ended
            .wait_while(tally, |tally| {
                let parks = tally.listener_open && tally.wake_failed.is_none();
                if parks {
                    (self.drain_parks)(tally.live.saturating_sub(tally.logouts));
                }
                parks
            })
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let (true, Some(why)) = (tally.listener_open, &tally.wake_failed) {
            tracing::warn!("could not wake the accept loop: {why}; ending with the listener open");
        }
    }

    /// Return once more than `since` connections have ended (`true`), or at once with `false` if
    /// none is live and none has ended since: then nothing is left that could end. Also returns
    /// `true` once the end is decided ([`Connections::settle`]): the caller reads its stop flag and
    /// returns, which is what the end waits for.
    ///
    /// `blocking` is called once, only if this has to block, and before it does. The lock is held
    /// then and released by the wait itself, so a connection that `blocking` causes to end does so
    /// after this is waiting. It must not take the lock (any `Live` dropped in it would).
    pub(super) fn wait_for_an_end(&self, since: u64, blocking: impl FnOnce()) -> bool {
        let mut blocking = Some(blocking);
        let mut tally = self.lock();
        loop {
            if tally.ended > since || tally.closing {
                return true;
            }
            if tally.live == 0 {
                return false;
            }
            if let Some(blocking) = blocking.take() {
                blocking();
            }
            tally = self
                .ended
                .wait(tally)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

/// A live connection that is a `logout` request; see [`Connections::begin_logout`].
pub(super) struct LogoutWait(Arc<Connections>);

impl Drop for LogoutWait {
    fn drop(&mut self) {
        self.0.change(|tally| tally.logouts -= 1);
    }
}

impl Live {
    /// Give this connection up as if it had never begun: it is not live any more, and has not
    /// ended. What is parked on the tally is woken, as the drain may now be done.
    pub(super) fn abandon(mut self) {
        if let Some(connections) = self.0.take() {
            connections.change(|tally| tally.live -= 1);
        }
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        if let Some(connections) = self.0.take() {
            connections.change(|tally| {
                tally.live -= 1;
                tally.ended += 1;
            });
        }
    }
}
