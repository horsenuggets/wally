//! Formats Wally's user-facing progress messages with the shared CLI palette. Muted values
//! (URLs and paths) are gray, counts are bold yellow, and every color is dropped when
//! `NO_COLOR` is set to a non-empty value. Paths always use forward slashes, collapse the
//! home folder to `~`, and end directories with `/`, on every platform.

use std::fmt::Display;
use std::io::IsTerminal;
use std::path::Path;

use log::{Level, Log, Metadata, Record};

// Raw SGR pairs match the exact codes the other CLIs use, where crossterm would emit
// 256-color sequences. Each pair closes only what it opened. Muted text uses the
// commandline-luau theme's gray (#a8a8a8) so it stays readable next to normal text.
const COUNT: (&str, &str) = ("1;93", "22;39");
const MUTED: (&str, &str) = ("38;2;168;168;168", "39");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Style {
    color: bool,
}

impl Style {
    pub fn new(color: bool) -> Self {
        Self { color }
    }

    pub fn from_stdout() -> Self {
        Self::from_stream(std::io::stdout().is_terminal())
    }

    pub fn from_stderr() -> Self {
        Self::from_stream(std::io::stderr().is_terminal())
    }

    fn from_stream(terminal: bool) -> Self {
        Self::new(color_enabled(
            std::env::var_os("NO_COLOR").as_deref(),
            std::env::var_os("CLICOLOR_FORCE").as_deref(),
            terminal,
        ))
    }

    pub fn muted(&self, text: impl Display) -> String {
        self.paint(MUTED, text)
    }

    pub fn count(&self, count: usize) -> String {
        self.paint(COUNT, count)
    }

    fn paint(&self, (open, close): (&str, &str), text: impl Display) -> String {
        if self.color {
            format!("\x1b[{}m{}\x1b[{}m", open, text, close)
        } else {
            text.to_string()
        }
    }
}

fn color_enabled(
    no_color: Option<&std::ffi::OsStr>,
    force: Option<&std::ffi::OsStr>,
    terminal: bool,
) -> bool {
    !matches!(no_color, Some(value) if !value.is_empty())
        && (terminal || matches!(force, Some(value) if !value.is_empty() && value != "0"))
}

/// The CLI renders its two progress records as plain sentences. Library consumers still
/// receive ordinary log records through their own logger, including their own filters.
pub struct ProgressLogger<F> {
    inner: env_logger::Logger,
    progress: F,
}

impl<F> ProgressLogger<F> {
    pub fn new(inner: env_logger::Logger, progress: F) -> Self {
        Self { inner, progress }
    }
}

impl<F: Fn(&Record<'_>) + Send + Sync> Log for ProgressLogger<F> {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        self.inner.enabled(metadata)
    }

    fn log(&self, record: &Record<'_>) {
        if !self.inner.matches(record) {
            return;
        }
        if record.level() == Level::Info
            && matches!(
                record.target(),
                "libwally::installation" | "libwally::package_index"
            )
        {
            (self.progress)(record);
        } else {
            self.inner.log(record);
        }
    }

    fn flush(&self) {
        self.inner.flush();
    }
}

fn plural<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 {
        singular
    } else {
        plural
    }
}

/// Shows a directory path with forward slashes, a `~` home prefix, and a trailing slash.
pub fn display_directory(path: &str, home: Option<&Path>) -> String {
    let mut display = path.replace('\\', "/");
    if let Some(home) = home.and_then(Path::to_str) {
        let home = home.replace('\\', "/");
        let home = home.trim_end_matches('/');
        // ASCII case folding preserves byte offsets, unlike Unicode lowercase expansion.
        let windows = display.as_bytes().get(1) == Some(&b':');
        let matches_home = display.get(..home.len()).is_some_and(|prefix| {
            if windows {
                prefix.eq_ignore_ascii_case(home)
            } else {
                prefix == home
            }
        });
        if !home.is_empty()
            && matches_home
            && (display.len() == home.len() || display.as_bytes().get(home.len()) == Some(&b'/'))
        {
            display = format!("~{}", &display[home.len()..]);
        }
    }
    format!("{}/", display.trim_end_matches('/')).replace(' ', "·")
}

/// Package indexes are usually URLs, but a local index is a directory on disk.
fn display_location(location: &str, home: Option<&Path>) -> String {
    if let Ok(url) = url::Url::parse(location) {
        if url.scheme() == "file" {
            if let Ok(path) = url.to_file_path() {
                return display_directory(&path.to_string_lossy(), home);
            }
        }
    }
    if location.contains("://") {
        location.to_owned()
    } else {
        display_directory(location, home)
    }
}

pub fn updating_index(style: Style, location: &str, home: Option<&Path>) -> String {
    format!(
        "Updating package index {}...",
        style.muted(display_location(location, home))
    )
}

pub fn downloaded(style: Style, count: usize) -> String {
    format!(
        "Downloaded {} {}!",
        style.count(count),
        plural(count, "package", "packages")
    )
}

pub fn refreshed(style: Style, count: usize) -> Option<String> {
    (count > 0).then(|| {
        format!(
            "Refreshed {} local package {}.",
            style.count(count),
            plural(count, "mirror", "mirrors")
        )
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;

    const PLAIN: Style = Style { color: false };
    const COLOR: Style = Style { color: true };

    #[test]
    fn color_respects_stream_capability_force_and_no_color() {
        for terminal in [false, true] {
            for no_color in [None, Some(OsStr::new("")), Some(OsStr::new("1"))] {
                for force in [
                    None,
                    Some(OsStr::new("")),
                    Some(OsStr::new("0")),
                    Some(OsStr::new("1")),
                ] {
                    let disabled = no_color.is_some_and(|value| !value.is_empty());
                    let forced = force.is_some_and(|value| !value.is_empty() && value != "0");
                    assert_eq!(
                        color_enabled(no_color, force, terminal),
                        !disabled && (terminal || forced)
                    );
                }
            }
        }
    }

    #[test]
    fn local_file_urls_display_as_paths_without_changing_remote_urls() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("My Index");
        let location = url::Url::from_directory_path(path).unwrap();
        assert_eq!(
            display_location(location.as_str(), Some(home.path())),
            "~/My·Index/"
        );
        assert_eq!(
            display_location("https://example.com/My%20Index", Some(home.path())),
            "https://example.com/My%20Index"
        );
    }

    #[test]
    fn cli_progress_preserves_logger_filters_and_other_log_destinations() {
        use std::sync::{Arc, Mutex};

        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        for filter in ["off", "trace", "trace/does-not-match"] {
            let enabled = filter == "trace";
            for target in [
                "libwally::installation",
                "libwally::package_index",
                "libwally::other",
            ] {
                for level in [Level::Info, Level::Warn] {
                    let normal = Arc::new(Mutex::new(Vec::new()));
                    let progress = Arc::new(Mutex::new(Vec::new()));
                    let sink = Arc::clone(&progress);
                    let inner = env_logger::Builder::new()
                        .parse_filters(filter)
                        .target(env_logger::Target::Pipe(Box::new(Capture(Arc::clone(
                            &normal,
                        )))))
                        .format(|buffer, record| {
                            use std::io::Write;
                            writeln!(buffer, "{}", record.args())
                        })
                        .build();
                    let logger = ProgressLogger::new(inner, move |record: &Record<'_>| {
                        sink.lock().unwrap().push(record.args().to_string())
                    });
                    logger.log(
                        &Record::builder()
                            .args(format_args!("A message."))
                            .level(level)
                            .target(target)
                            .build(),
                    );
                    let plain = enabled && level == Level::Info && target != "libwally::other";
                    assert_eq!(
                        *progress.lock().unwrap(),
                        if plain { vec!["A message."] } else { vec![] }
                    );
                    assert_eq!(
                        *normal.lock().unwrap(),
                        if enabled && !plain {
                            b"A message.\n".to_vec()
                        } else {
                            vec![]
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn plain_style_has_no_escape_codes() {
        let messages = [
            updating_index(PLAIN, "https://github.com/UpliftGames/wally-index", None),
            downloaded(PLAIN, 3),
            refreshed(PLAIN, 2).unwrap(),
        ];
        for message in messages {
            assert!(!message.contains('\x1b'), "{:?}", message);
        }
    }

    #[test]
    fn colored_style_uses_the_shared_palette() {
        assert_eq!(COLOR.muted("x"), "\x1b[38;2;168;168;168mx\x1b[39m");
        assert_eq!(COLOR.count(15), "\x1b[1;93m15\x1b[22;39m");
        assert_eq!(
            downloaded(COLOR, 1),
            "Downloaded \x1b[1;93m1\x1b[22;39m package!"
        );
        assert_eq!(
            updating_index(COLOR, "https://example.com/index", None),
            "Updating package index \x1b[38;2;168;168;168mhttps://example.com/index\x1b[39m..."
        );
    }

    #[test]
    fn index_messages_end_with_an_ellipsis() {
        assert_eq!(
            updating_index(PLAIN, "https://github.com/UpliftGames/wally-index", None),
            "Updating package index https://github.com/UpliftGames/wally-index..."
        );
    }

    #[test]
    fn download_counts_handle_singular_and_plural() {
        assert_eq!(downloaded(PLAIN, 0), "Downloaded 0 packages!");
        assert_eq!(downloaded(PLAIN, 1), "Downloaded 1 package!");
        assert_eq!(downloaded(PLAIN, 15), "Downloaded 15 packages!");
    }

    #[test]
    fn refresh_counts_handle_singular_plural_and_silence() {
        assert_eq!(refreshed(PLAIN, 0), None);
        assert_eq!(
            refreshed(PLAIN, 1).unwrap(),
            "Refreshed 1 local package mirror."
        );
        assert_eq!(
            refreshed(PLAIN, 4).unwrap(),
            "Refreshed 4 local package mirrors."
        );
    }

    #[test]
    fn local_indexes_display_as_normalized_directories() {
        let unix_home = Path::new("/home/user");
        assert_eq!(
            display_location("/home/user/indexes/test", Some(unix_home)),
            "~/indexes/test/"
        );
        assert_eq!(
            display_location("/home/username/index/", Some(unix_home)),
            "/home/username/index/"
        );
        assert_eq!(display_location("/home/user", Some(unix_home)), "~/");
        assert_eq!(
            display_location("/home/user/My Index", Some(unix_home)),
            "~/My·Index/"
        );
        assert_eq!(
            display_location("C:/İ/index", Some(Path::new("C:/i\u{307}"))),
            "C:/İ/index/"
        );

        let windows_home = Path::new("C:\\Users\\User");
        assert_eq!(
            display_location("c:\\users\\user\\index", Some(windows_home)),
            "~/index/"
        );
        assert_eq!(
            display_location("D:\\index\\", Some(windows_home)),
            "D:/index/"
        );
    }
}
