use std::io::Read;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;

use anyhow::{ensure, Context};
use structopt::StructOpt;

use crate::local_sync::{LocalSync, SourceChanged};
use crate::terminal_style::{self, Style};

const WATCH_INTERVAL: Duration = Duration::from_millis(250);

/// Refresh installed copies of declared local packages without downloading dependencies.
#[derive(Debug, StructOpt)]
pub struct SyncLocalSubcommand {
    /// Path to the project whose installed local packages should be refreshed.
    #[structopt(long = "project-path", default_value = ".")]
    pub project_path: PathBuf,

    /// Keep generated local package copies synchronized with their original sources.
    #[structopt(long)]
    pub watch: bool,

    /// Stop watching when the owning process closes standard input.
    #[structopt(long, requires = "watch")]
    pub shutdown_on_stdin_eof: bool,
}

impl SyncLocalSubcommand {
    pub fn run(self) -> anyhow::Result<()> {
        ensure!(
            self.watch || !self.shutdown_on_stdin_eof,
            "Standard-input ownership requires watch mode."
        );
        let mut sync = None;
        let receiver = self.shutdown_on_stdin_eof.then(|| {
            let (shutdown, receiver) = mpsc::channel();
            std::thread::spawn(move || {
                let result = wait_for_eof(std::io::stdin().lock());
                let _ = shutdown.send(result);
            });
            receiver
        });
        synchronize(
            || {
                if sync.is_none() {
                    sync = Some(LocalSync::new(&self.project_path)?);
                }
                sync.as_mut().unwrap().refresh()
            },
            self.watch,
            receiver,
            || {
                println!("Local package mirrors are synchronized.");
            },
        )
    }
}

fn synchronize(
    mut refresh: impl FnMut() -> anyhow::Result<usize>,
    watch: bool,
    receiver: Option<Receiver<std::io::Result<()>>>,
    mut announce_ready: impl FnMut(),
) -> anyhow::Result<()> {
    let mut ready = false;
    loop {
        match refresh() {
            Ok(count) => {
                if ready {
                    report_refresh(count);
                } else {
                    announce_ready();
                    ready = true;
                }
            }
            Err(error) if watch && error.is::<SourceChanged>() => log::warn!("{error}"),
            Err(error) => return Err(error),
        }
        if !watch {
            return Ok(());
        }
        if let Some(receiver) = &receiver {
            match receiver.recv_timeout(WATCH_INTERVAL) {
                Ok(result) => {
                    return result.context("Could not monitor the owning process's standard input.")
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    anyhow::bail!("The standard-input ownership monitor stopped unexpectedly.")
                }
            }
        } else {
            std::thread::sleep(WATCH_INTERVAL);
        }
    }
}

fn report_refresh(count: usize) {
    if let Some(message) = terminal_style::refreshed(Style::from_stdout(), count) {
        println!("{message}");
    }
}

fn wait_for_eof(mut input: impl Read) -> std::io::Result<()> {
    let mut buffer = [0; 1024];
    loop {
        match input.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_retries_initial_source_changes_before_announcing_readiness() {
        let attempts = std::cell::Cell::new(0);
        let announced_at = std::cell::Cell::new(0);
        let (shutdown, receiver) = mpsc::channel();
        synchronize(
            || {
                attempts.set(attempts.get() + 1);
                if attempts.get() <= 3 {
                    return Err(SourceChanged.into());
                }
                shutdown.send(Ok(())).unwrap();
                Ok(1)
            },
            true,
            Some(receiver),
            || announced_at.set(attempts.get()),
        )
        .unwrap();
        assert_eq!(attempts.get(), 4);
        assert_eq!(announced_at.get(), 4);
    }

    #[test]
    fn ownership_can_stop_retries_before_readiness() {
        let attempts = std::cell::Cell::new(0);
        let announced = std::cell::Cell::new(false);
        let (shutdown, receiver) = mpsc::channel();
        synchronize(
            || {
                attempts.set(attempts.get() + 1);
                shutdown.send(Ok(())).unwrap();
                Err(SourceChanged.into())
            },
            true,
            Some(receiver),
            || announced.set(true),
        )
        .unwrap();
        assert_eq!(attempts.get(), 1);
        assert!(!announced.get());
    }

    #[test]
    fn one_shot_source_changes_fail_without_announcing_readiness() {
        let announced = std::cell::Cell::new(false);
        let error = synchronize(
            || Err(SourceChanged.into()),
            false,
            None,
            || announced.set(true),
        )
        .unwrap_err();
        assert!(error.is::<SourceChanged>());
        assert!(!announced.get());
    }

    #[test]
    fn ownership_waits_for_eof_instead_of_the_first_input_bytes() {
        struct Chunks(usize);
        impl Read for Chunks {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                self.0 += 1;
                if self.0 < 3 {
                    output[0] = b'x';
                    Ok(1)
                } else {
                    Ok(0)
                }
            }
        }
        let mut input = Chunks(0);
        wait_for_eof(&mut input).unwrap();
        assert_eq!(input.0, 3);
    }
}
