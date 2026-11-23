//! Formats Wally's user-facing progress messages with the shared CLI palette. Muted values
//! (URLs and paths) are gray, counts are bold yellow, and every color is dropped when
//! `NO_COLOR` is set to a non-empty value. Paths always use forward slashes, collapse the
//! home folder to `~`, and end directories with `/`, on every platform.

use std::fmt::Display;
use std::path::Path;

// Raw SGR pairs keep the 16-color codes the other CLIs use, where crossterm would emit
// 256-color sequences. Each pair closes only what it opened.
const COUNT: (&str, &str) = ("1;93", "22;39");
const MUTED: (&str, &str) = ("90", "39");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Style {
    color: bool,
}

impl Style {
    pub fn new(color: bool) -> Self {
        Self { color }
    }

    /// Follows the `NO_COLOR` convention, where any non-empty value disables color.
    pub fn from_env() -> Self {
        Self::new(color_enabled(std::env::var_os("NO_COLOR").as_deref()))
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

fn color_enabled(no_color: Option<&std::ffi::OsStr>) -> bool {
    !matches!(no_color, Some(value) if !value.is_empty())
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
        // Windows paths compare case-insensitively, so only fold case for drive paths.
        let windows = display.as_bytes().get(1) == Some(&b':');
        let (candidate, prefix) = if windows {
            (display.to_lowercase(), home.to_lowercase())
        } else {
            (display.clone(), home.to_owned())
        };
        if !prefix.is_empty()
            && (candidate == prefix || candidate.starts_with(&format!("{prefix}/")))
        {
            display = format!("~{}", &display[home.len()..]);
        }
    }
    format!("{}/", display.trim_end_matches('/'))
}

/// Package indexes are usually URLs, but a local index is a directory on disk.
fn display_location(location: &str, home: Option<&Path>) -> String {
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
    fn no_color_disables_color_only_when_non_empty() {
        assert!(color_enabled(None));
        assert!(color_enabled(Some(OsStr::new(""))));
        assert!(!color_enabled(Some(OsStr::new("1"))));
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
        assert_eq!(COLOR.muted("x"), "\x1b[90mx\x1b[39m");
        assert_eq!(COLOR.count(15), "\x1b[1;93m15\x1b[22;39m");
        assert_eq!(
            downloaded(COLOR, 1),
            "Downloaded \x1b[1;93m1\x1b[22;39m package!"
        );
        assert_eq!(
            updating_index(COLOR, "https://example.com/index", None),
            "Updating package index \x1b[90mhttps://example.com/index\x1b[39m..."
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
