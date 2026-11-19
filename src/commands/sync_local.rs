use std::io::Read;
use std::path::PathBuf;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

use anyhow::{ensure, Context};
use structopt::StructOpt;

use crate::local_sync::{LocalSync, SourceChanged};

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
        let mut sync = LocalSync::new(&self.project_path)?;
        sync.refresh()?;
        println!("Local package mirrors are synchronized.");
        if !self.watch {
            return Ok(());
        }
        let receiver = self.shutdown_on_stdin_eof.then(|| {
            let (shutdown, receiver) = mpsc::channel();
            std::thread::spawn(move || {
                let result = wait_for_eof(std::io::stdin().lock());
                let _ = shutdown.send(result);
            });
            receiver
        });
        loop {
            if let Some(receiver) = &receiver {
                match receiver.recv_timeout(WATCH_INTERVAL) {
                    Ok(result) => {
                        return result
                            .context("Could not monitor the owning process's standard input.")
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => {
                        anyhow::bail!("The standard-input ownership monitor stopped unexpectedly.")
                    }
                }
            } else {
                std::thread::sleep(WATCH_INTERVAL);
            }
            match sync.refresh() {
                Ok(count) => report_refresh(count),
                Err(error) if error.is::<SourceChanged>() => log::warn!("{error}"),
                Err(error) => return Err(error),
            }
        }
    }
}

fn report_refresh(count: usize) {
    if count > 0 {
        println!(
            "Refreshed {count} local package {}.",
            if count == 1 { "mirror" } else { "mirrors" }
        );
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
