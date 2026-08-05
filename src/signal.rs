use bitcoin::BlockHash;
use crossbeam_channel::{self as channel, after, select};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use signal_hook::consts::{SIGINT, SIGTERM, SIGUSR1};

use crate::errors::*;

// Process-wide shutdown level, stamped by the signal thread (which also logs
// the signal number). A terminating signal is process-scoped state, so it
// lives here as a static observed by long-running producers (the block
// fetchers) instead of being threaded through every signature on that path.
// Sticky and read-only for observers, unlike the bounded(1) channel below
// whose single buffered message wait() consumes.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

pub fn shutdown_requested() -> bool {
    SHUTDOWN.load(Ordering::Relaxed)
}

#[derive(Clone)] // so multiple threads could wait on signals
pub struct Waiter {
    receiver: channel::Receiver<i32>,
    zmq_receiver: channel::Receiver<BlockHash>,
}

fn notify(signals: &[i32]) -> channel::Receiver<i32> {
    let (s, r) = channel::bounded(1);
    let mut signals =
        signal_hook::iterator::Signals::new(signals).expect("failed to register signal hook");
    thread::spawn(move || {
        for signal in signals.forever() {
            if signal != SIGUSR1 {
                info!("received signal {} — shutdown requested", signal);
                SHUTDOWN.store(true, Ordering::Relaxed);
            }
            s.send(signal)
                .unwrap_or_else(|_| panic!("failed to send signal {}", signal));
        }
    });
    r
}

impl Waiter {
    pub fn start(block_hash_receive: channel::Receiver<BlockHash>) -> Waiter {
        Waiter {
            receiver: notify(&[
                SIGINT, SIGTERM,
                SIGUSR1, // allow external triggering (e.g. via bitcoind `blocknotify`)
            ]),
            zmq_receiver: block_hash_receive,
        }
    }

    pub fn wait(&self, duration: Duration, accept_block_notification: bool) -> Result<()> {
        let start = Instant::now();
        select! {
            recv(self.receiver) -> msg => {
                match msg {
                    Ok(sig) if sig == SIGUSR1 => {
                        trace!("notified via SIGUSR1");
                        if accept_block_notification {
                            Ok(())
                        } else {
                            let wait_more = duration.saturating_sub(start.elapsed());
                            self.wait(wait_more, accept_block_notification)
                        }
                    }
                    Ok(sig) => bail!(ErrorKind::Interrupt(sig)),
                    Err(_) => bail!("signal hook channel disconnected"),
                }
            },
            recv(self.zmq_receiver) -> msg => {
                match msg {
                    Ok(_) => {
                        if accept_block_notification {
                            Ok(())
                        } else {
                            let wait_more = duration.saturating_sub(start.elapsed());
                            self.wait(wait_more, accept_block_notification)
                        }
                    }
                    Err(_) => bail!("signal hook channel disconnected"),
                }
            },
            recv(after(duration)) -> _ => Ok(()),

        }
    }
}
