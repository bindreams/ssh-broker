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
    /// The shortage that decided the end, set with `closing` in the same step.
    fatal_cause: Option<String>,
    /// The listeners the accept loops hold (`agent.sock`, and `request.sock` where the agent keeps one), each
    /// with the way to wake its loop.
    listeners: Vec<Registered>,
    /// The next [`Registered::id`].
    next_listener: u64,
}

/// A listener an accept loop holds, as the tally knows it.
struct Registered {
    id: u64,
    /// Which socket it is, for the log.
    socket: &'static str,
    wake: WakeConnect,
    /// Why the loop could not be woken, if it could not: nothing will make it return, so the end does not
    /// wait for it.
    wake_failed: Option<String>,
}

/// A connect to a listener of this agent, which makes the accept loop blocked on it return from `accept`.
pub(super) type WakeConnect = Arc<dyn Fn() -> anyhow::Result<()> + Send + Sync>;

/// A listener that is registered with the tally; see [`Connections::listener_opened`]. Dropping it is the
/// loop having returned; its listener is closed right after.
pub(super) struct OpenListener {
    connections: Arc<Connections>,
    id: u64,
}

impl Drop for OpenListener {
    fn drop(&mut self) {
        self.connections.change(|tally| {
            let before = tally.listeners.len();
            tally.listeners.retain(|listener| listener.id != self.id);
            debug_assert!(
                tally.listeners.len() < before,
                "a listener closed that was never opened"
            );
        });
    }
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
                fatal_cause: None,
                listeners: Vec::new(),
                next_listener: 0,
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

    /// Whether an accept loop holds a listener.
    #[cfg(test)]
    pub(super) fn listener_is_open(&self) -> bool {
        !self.lock().listeners.is_empty()
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

    /// An accept loop is about to run over a listener of `socket`: register it with `wake`, the connect
    /// that makes the loop return from `accept`. The listener counts as held until the guard is dropped,
    /// which the loop does once it has returned, and before it closes the listener: a wake that arrives then
    /// is for a loop that is gone, and a failure of it is not reported ([`Connections::wake_failed`]).
    ///
    /// The loop calls this before its first look at the flag [`Connections::is_closing`], so whichever way
    /// the end is decided relative to it, the loop stops: an end decided before the registration finds
    /// nothing to wake or wait for, and the loop reads the flag up and returns without blocking; an end
    /// decided after wakes it ([`Connections::settle`]).
    pub(super) fn listener_opened(self: &Arc<Self>, socket: &'static str, wake: WakeConnect) -> OpenListener {
        let id = self.change(|tally| {
            let id = tally.next_listener;
            tally.next_listener += 1;
            tally.listeners.push(Registered {
                id,
                socket,
                wake,
                wake_failed: None,
            });
            id
        });
        OpenListener {
            connections: Arc::clone(self),
            id,
        }
    }

    /// Decide the end of the agent on the shortage `cause`, if no connection is live and none has ended since the
    /// count `since` (the one the loop's wait saw, [`Connections::wait_for_an_end`]), in one step under the tally's
    /// lock: the flag [`Connections::is_closing`] reads is up, and [`Connections::fatal_cause`] set, when this
    /// returns `true`. A connection counted after finds the flag up (a login is refused, see `Control::is_ending`);
    /// one counted before, or that ended since `since` and may have freed what the loop lacks, keeps the end
    /// undecided (`false`).
    pub(super) fn decide_end_if_idle(&self, since: u64, cause: &anyhow::Error) -> bool {
        let cause = format!("{cause:#}");
        self.change(|tally| {
            let idle = tally.live == 0 && tally.ended == since;
            if idle {
                tally.closing = true;
                tally.fatal_cause.get_or_insert(cause);
            }
            idle
        })
    }

    /// The shortage that decided the end ([`Connections::decide_end_if_idle`]), if one did: the first, written in
    /// the same step that raised the flag. An end that a `logout` decided has none.
    pub(super) fn fatal_cause(&self) -> Option<String> {
        self.lock().fatal_cause.clone()
    }

    /// Whether the end is decided: the accept loop stops after its current accept.
    pub(super) fn is_closing(&self) -> bool {
        self.lock().closing
    }

    /// The loop of listener `id` cannot be woken, so waiting for it would not end: the end goes on without
    /// it, and says why (see [`Connections::settle`]). A listener that is no longer registered is nothing
    /// to report: its loop did return, and a connect that found its listener closed after that is no failure.
    fn wake_failed(&self, id: u64, why: &str) {
        self.change(|tally| {
            if let Some(listener) = tally.listeners.iter_mut().find(|listener| listener.id == id) {
                listener.wake_failed.get_or_insert_with(|| why.to_string());
            }
        });
    }

    /// Decide the end of the agent: wait until only `logout` requests are live, stop the accept loops
    /// (every listener registered by [`Connections::listener_opened`]: `agent.sock`'s, and `request.sock`'s
    /// where the agent keeps one) and close their listeners, and judge again. Returns how the last judgement
    /// went. Any number of callers (the `logout` handlers, the thread that ran the loop) may ask; the first
    /// does the work and the others wait for it.
    ///
    /// Waits with the listeners open (a login meanwhile gets the refusal), stops and closes the listeners, then
    /// judges again; the second judgement sees every connection a loop took, since a loop counts a connection
    /// before it reads the flag. A first wait that gave up is not repeated.
    pub(super) fn settle(self: &Arc<Self>) -> Drained {
        *self.settled.get_or_init(|| {
            let first = self.wait_until_only_logouts_live();
            self.close_listeners();
            match first {
                Drained::Complete => self.wait_until_only_logouts_live(),
                abandoned @ Drained::Abandoned { .. } => abandoned,
            }
        })
    }

    /// Raise the flag, wake the loops of the listeners registered now, and wait until every one of them has
    /// returned (it closes its listener right after), or its wake has failed. Nothing is waited for if no loop holds a
    /// listener. Each wake is made on a thread of its own ([`Connections::wake_without_blocking`]).
    fn close_listeners(self: &Arc<Self>) {
        // The change wakes a loop parked for a resource (see `wait_for_an_end`): it is not in
        // `accept`, where the wake reaches it.
        let to_wake: Vec<_> = self.change(|tally| {
            tally.closing = true;
            tally
                .listeners
                .iter()
                .map(|listener| (listener.id, listener.socket, Arc::clone(&listener.wake)))
                .collect()
        });
        if to_wake.is_empty() {
            return;
        }
        for (id, socket, wake) in to_wake {
            self.wake_without_blocking(id, socket, wake);
        }
        let tally = self.lock();
        let tally = self
            .ended
            .wait_while(tally, |tally| {
                let parks = tally.listeners.iter().any(|listener| listener.wake_failed.is_none());
                if parks {
                    (self.drain_parks)(tally.live.saturating_sub(tally.logouts));
                }
                parks
            })
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for listener in &tally.listeners {
            if let Some(why) = &listener.wake_failed {
                tracing::warn!(
                    "could not wake the accept loop of {}: {why}; not waiting for it",
                    listener.socket
                );
            }
        }
    }

    /// Run `wake` (the connect to `socket`'s listener `id`) on a thread of its own so the caller never waits: a
    /// connect to a full queue may block, and a full queue means the loop is not in `accept` and will read the
    /// flag before its next one. A failed wake or thread is recorded against the listener.
    fn wake_without_blocking(self: &Arc<Self>, id: u64, socket: &'static str, wake: WakeConnect) {
        let on_thread = Arc::clone(self);
        let started = std::thread::Builder::new()
            .name(format!("wake-{socket}"))
            .spawn(move || {
                if let Err(e) = wake() {
                    on_thread.wake_failed(id, &format!("{e:#}"));
                }
            });
        if let Err(e) = started {
            self.wake_failed(id, &format!("no thread for it: {e}"));
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

/// A listener registered with the tally that a test closes from any thread, as its loop does: by [`HeldListener::close`],
/// or when the end wakes it, if `on_wake` says so.
#[cfg(test)]
pub(super) struct HeldListener(Mutex<Option<OpenListener>>);

#[cfg(test)]
impl HeldListener {
    /// Register a listener of `socket`. When the end wakes it, `on_wake` is called with the listener, which stays
    /// held until it is closed (by `on_wake`, or by the test).
    pub(super) fn open(
        connections: &Arc<Connections>,
        socket: &'static str,
        on_wake: impl Fn(&HeldListener) + Send + Sync + 'static,
    ) -> Arc<HeldListener> {
        Arc::new_cyclic(|this: &std::sync::Weak<HeldListener>| {
            let this = this.clone();
            let wake: WakeConnect = Arc::new(move || {
                if let Some(listener) = this.upgrade() {
                    on_wake(&listener);
                }
                Ok(())
            });
            HeldListener(Mutex::new(Some(connections.listener_opened(socket, wake))))
        })
    }

    /// The loop returned and its listener is closed. Does nothing the second time.
    pub(super) fn close(&self) {
        let open = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
        drop(open);
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
