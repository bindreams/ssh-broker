//! What the agent's tests of a session's connection share: an in-memory write half that records what is written, and
//! a target that records what it is given.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};

use super::HalfClose;
use super::link::InputTarget;
use crate::protocol::{FrameKind, FrameReader, Stream};

/// A gate a write can be held at: `entered` says that a write has reached it, and the write goes on once `release` is
/// called.
#[derive(Clone)]
pub(super) struct Gate {
    entered: mpsc::Sender<()>,
    open: Arc<(Mutex<bool>, Condvar)>,
}

impl Gate {
    fn new() -> (Gate, mpsc::Receiver<()>) {
        let (entered, at_gate) = mpsc::channel();
        let gate = Gate {
            entered,
            open: Arc::new((Mutex::new(false), Condvar::new())),
        };
        (gate, at_gate)
    }

    pub(super) fn release(&self) {
        *self.open.0.lock().unwrap() = true;
        self.open.1.notify_all();
    }

    fn pass(&self) {
        let _ = self.entered.send(());
        let mut open = self.open.0.lock().unwrap();
        while !*open {
            open = self.open.1.wait(open).unwrap();
        }
    }
}

/// The connection's write half: what was written, whether the half was closed, and a gate the first write waits at.
#[derive(Clone, Default)]
pub(super) struct Wire {
    pub(super) written: Arc<Mutex<Vec<u8>>>,
    pub(super) closed: Arc<AtomicBool>,
    gate: Arc<Mutex<Option<Gate>>>,
}

impl Wire {
    /// The frames written so far, as `(kind, payload)`.
    pub(super) fn frames(&self) -> Vec<(FrameKind, Vec<u8>)> {
        let mut reader = FrameReader::new();
        reader.push(&self.written.lock().unwrap());
        let mut frames = Vec::new();
        while let Some(frame) = reader.next_frame().unwrap() {
            frames.push((frame.kind, frame.payload));
        }
        assert_eq!(reader.buffered_len(), 0, "a frame was cut");
        frames
    }

    /// The data frames written so far, as text with the stream's tag in front: `P` for the terminal's, `O` and
    /// `E` for stdout and stderr.
    pub(super) fn data(&self) -> Vec<String> {
        self.frames()
            .into_iter()
            .filter(|(kind, _)| *kind == FrameKind::Data)
            .map(|(_, payload)| {
                let tag = match Stream::from_u8(payload[0]).unwrap() {
                    Stream::Pty => 'P',
                    Stream::Stdin => 'I',
                    Stream::Stdout => 'O',
                    Stream::Stderr => 'E',
                };
                format!("{tag}{}", String::from_utf8_lossy(&payload[1..]))
            })
            .collect()
    }

    /// Hold the next write at a gate.
    pub(super) fn hold_next_write(&self) -> (Gate, mpsc::Receiver<()>) {
        let (gate, at_gate) = Gate::new();
        *self.gate.lock().unwrap() = Some(gate.clone());
        (gate, at_gate)
    }
}

impl std::io::Write for Wire {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let held = self.gate.lock().unwrap().take();
        if let Some(gate) = held {
            gate.pass();
        }
        self.written.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl HalfClose for Wire {
    fn shutdown_write(&self) -> anyhow::Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

/// The write half of a connection whose peer has gone: every write fails, and the FIN has nothing to do.
impl HalfClose for crate::test_support::ClosedStream {
    fn shutdown_write(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

/// A target that records what it was given.
#[derive(Default)]
pub(super) struct Recorder {
    events: Mutex<Vec<String>>,
    /// Every input is recorded and then fails, as the input of a pseudoconsole that has been closed does.
    fails: bool,
}

impl Recorder {
    /// A target whose input fails.
    pub(super) fn failing() -> Recorder {
        Recorder {
            fails: true,
            ..Recorder::default()
        }
    }

    pub(super) fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
}

impl InputTarget for Recorder {
    fn input(&self, bytes: &[u8]) -> anyhow::Result<()> {
        self.events
            .lock()
            .unwrap()
            .push(format!("input {}", String::from_utf8_lossy(bytes)));
        anyhow::ensure!(!self.fails, "the target's input is closed");
        Ok(())
    }

    fn resize(&self, cols: u16, rows: u16) {
        self.events.lock().unwrap().push(format!("resize {cols}x{rows}"));
    }
}
