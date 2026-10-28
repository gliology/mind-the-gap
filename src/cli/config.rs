//! Defaults: the config files, and what `set` adds to them in a session.
//!
//! A default is an option's long name and a value, and it becomes clap's own default for that
//! option, so precedence falls out of clap: a flag beats its environment variable, which beats
//! the default. Below that the defaults come in layers, the image's file, the user's, the
//! environment a session takes in, and `set`, each over the one before, and an applet's
//! table counts within its own layer: a `[piv]` value in a file never beats a `set`.
//!
//! The files are TOML, of which this reads the part a flat table of options needs: comments,
//! `name = value` with a string, a boolean, an integer or an array of strings. Secrets are
//! never defaults: no file and no `set` can hold a seed, a password or a pin.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};

use clap::Command;

use super::App;

/// The config file of the live image, written from its NixOS configuration and read-only
pub(super) const IMAGE_PATH: &str = "/etc/mind-the-gap/config.toml";

/// Options that carry secrets, which never become defaults
const SECRETS: [&str; 10] = [
    "seed",
    "password",
    "card-seed",
    "card-password",
    "key-seed",
    "key-password",
    "from-key-seed",
    "from-key-password",
    "pin",
    "current-pin",
];

/// Options that belong to one invocation and say nothing about the next
const PER_COMMAND: [&str; 6] = ["yes", "dry-run", "to", "config", "plumbing", "log-level"];

/// The user's config file: `$XDG_CONFIG_HOME/mind-the-gap/config.toml`
pub(super) fn user_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    Some(base.join("mind-the-gap").join("config.toml"))
}

/// One default's value
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Value {
    Text(String),
    Flag(bool),
    List(Vec<String>),
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Text(text) => f.write_str(text),
            Value::Flag(flag) => write!(f, "{flag}"),
            Value::List(items) => f.write_str(&items.join(",")),
        }
    }
}

/// Where a default comes from, weakest first, named as the book names the layers
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Layer {
    Image,
    User,
    Environment,
    Set,
}

impl Layer {
    fn name(self) -> &'static str {
        match self {
            Layer::Image => "image",
            Layer::User => "user",
            Layer::Environment => "environment",
            Layer::Set => "set",
        }
    }
}

/// A config file a layer is read from, and whether it was there to read
#[derive(Clone, Debug)]
struct ConfigFile {
    layer: Layer,
    /// None where there is no home to find the user's file in
    path: Option<PathBuf>,
    read: bool,
    /// Named with `--config`, which has to be there
    named: bool,
}

/// Defaults by option long name, each layer's
#[derive(Clone, Debug, Default)]
pub(super) struct Defaults {
    values: BTreeMap<String, BTreeMap<Layer, Value>>,
    /// The files consulted, the image's and the user's, for a listing to name
    files: Vec<ConfigFile>,
}

impl Defaults {
    /// The defaults of the image's file and the user's (or `user`, from `--config`), the
    /// user's winning
    pub(super) fn load(user: Option<&Path>) -> Result<Defaults> {
        let mut defaults = Defaults::default();
        let image = Path::new(IMAGE_PATH);
        let read = image.exists();
        if read {
            defaults.read(image, Layer::Image)?;
        }
        defaults.files.push(ConfigFile {
            layer: Layer::Image,
            path: Some(image.into()),
            read,
            named: false,
        });
        // A file named with --config has to be there but for `set --save`, which may create
        // it (see `require_named_file`); the user's own may not be there yet
        let named = user.is_some();
        let path = user.map(Path::to_path_buf).or_else(user_path);
        let read = path.as_deref().is_some_and(Path::exists);
        if let (Some(path), true) = (&path, read) {
            defaults.read(path, Layer::User)?;
        }
        defaults
            .files
            .push(ConfigFile { layer: Layer::User, path, read, named });
        Ok(defaults)
    }

    /// Refuse a run that reads defaults from a `--config` file that is not there, rather than
    /// go on without them; only `set --save`, which creates it, may
    pub(super) fn require_named_file(&self) -> Result<()> {
        match self.files.iter().find(|file| file.named && !file.read) {
            Some(file) => bail!(
                "Cannot read the config file {}: there is none; `set --save` creates it",
                file.path.as_deref().unwrap_or(Path::new("")).display()
            ),
            None => Ok(()),
        }
    }

    /// Read one file into its layer, each value checked by its option's own parser, so that
    /// a typo names the file rather than surfacing later as a flag nobody gave
    fn read(&mut self, path: &Path, layer: Layer) -> Result<()> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read the config file {}", path.display()))?;
        let origin = path.display().to_string();
        let command = super::command();
        for (name, value) in parse(&text).with_context(|| format!("In {origin}"))? {
            self.insert(&name, value.clone(), layer)
                .and_then(|()| check(option_of(&name), &value, &command))
                .with_context(|| format!("In {origin}"))?;
        }
        Ok(())
    }

    /// The value in force for a key: that of its strongest layer
    fn effective(&self, key: &str) -> Option<(Layer, &Value)> {
        self.values
            .get(key)
            .and_then(|layers| layers.last_key_value())
            .map(|(layer, value)| (*layer, value))
    }

    /// Set one default, checking the name against the option table; `piv.<name>` and
    /// `pgp.<name>` are defaults for that applet alone
    fn insert(&mut self, key: &str, value: Value, layer: Layer) -> Result<()> {
        refuse_unfit_key(key)?;
        self.values
            .entry(key.to_string())
            .or_default()
            .insert(layer, value);
        Ok(())
    }

    /// The defaults one applet's half of a command takes: the general ones, with that
    /// applet's table over them where it is set in the same layer or a stronger one
    pub(super) fn for_app(&self, app: App) -> Defaults {
        let prefix = format!("{}.", table_of(app));
        let mut values: BTreeMap<String, BTreeMap<Layer, Value>> = BTreeMap::new();
        for key in self.values.keys().filter(|key| !key.contains('.')) {
            if let Some((layer, value)) = self.effective(key) {
                values.insert(key.clone(), BTreeMap::from([(layer, value.clone())]));
            }
        }
        for key in self.values.keys() {
            let (Some(name), Some((layer, value))) =
                (key.strip_prefix(&prefix), self.effective(key))
            else {
                continue;
            };
            let general = values
                .get(name)
                .and_then(|layers| layers.keys().next_back());
            if general.is_none_or(|general| *general <= layer) {
                values.insert(name.to_string(), BTreeMap::from([(layer, value.clone())]));
            }
        }
        Defaults { values, files: self.files.clone() }
    }

    /// Whether any default is one applet's alone
    pub(super) fn has_tables(&self) -> bool {
        self.values.keys().any(|key| key.contains('.'))
    }

    /// Set defaults from `name=value` words, as `set` takes them; the value is checked by
    /// the option's own parser, so a typo is caught here rather than on every later command
    pub(super) fn set(&mut self, settings: &[String]) -> Result<()> {
        let command = super::command();
        for setting in settings {
            let (name, value) = setting
                .split_once('=')
                .ok_or_else(|| anyhow!("`{setting}` is not name=value"))?;
            // The name first, as written, so that a typo behind a table is answered with the
            // setting of that table
            refuse_unfit_key(name)?;
            let value = parse_word(option_of(name), value, &command)?;
            self.insert(name, value, Layer::Set)?;
        }
        Ok(())
    }

    /// Forget each name's default in force, back to the one beneath it: what `set` stored
    /// gives way to the environment's or a file's, and those to the built-in one
    pub(super) fn unset(&mut self, names: &[String]) -> Result<()> {
        for name in names {
            let Some(layers) = self.values.get_mut(name) else {
                bail!("`{name}` has no default to forget");
            };
            layers.pop_last();
            if layers.is_empty() {
                self.values.remove(name);
            }
        }
        Ok(())
    }

    /// The user's config file, which `--save` writes: the one `--config` names, or the
    /// user's own
    pub(super) fn user_file(&self) -> Option<&Path> {
        self.files
            .iter()
            .find(|file| file.layer == Layer::User)
            .and_then(|file| file.path.as_deref())
    }

    /// Set defaults as `set` does, and write them to the user's config file too
    ///
    /// Every word is checked before the file is touched, by the same table and parsers as
    /// `set`, so a secret, an option of one command or a typo leaves the file as it was.
    pub(super) fn save(&mut self, settings: &[String]) -> Result<()> {
        let path = self.writable_file()?;
        let mut checked = self.clone();
        checked.set(settings)?;
        let before = existing(&path)?;
        let mut text = before.clone();
        let mut saved = Vec::new();
        for setting in settings {
            let (key, _) = setting.split_once('=').expect("checked by set");
            let (_, value) = checked.effective(key).expect("set by set");
            text = with_setting(&text, key, value);
            saved.push((key.to_string(), Some(value.clone())));
        }
        refuse_stray_edits(&path, &before, &text, &saved)?;
        write(&path, &text)?;
        self.mark_read();
        for (key, value) in saved {
            let value = value.expect("saved with its value");
            self.insert(&key, value.clone(), Layer::User)?;
            self.insert(&key, value, Layer::Set)?;
        }
        log::info!("Saved {} in {}", names_of(settings), path.display());
        Ok(())
    }

    /// Forget defaults as `unset` does, and take them out of the user's config file too
    ///
    /// What the session's `set` holds and what the file holds go both, so the default falls
    /// back to the environment's, the image's or the built-in one; a name neither had is an
    /// error, and leaves the file as it was.
    pub(super) fn unsave(&mut self, names: &[String]) -> Result<()> {
        let path = self.writable_file()?;
        let before = existing(&path)?;
        let mut text = before.clone();
        let mut removed = Vec::new();
        for name in names {
            let set = self
                .values
                .get(name)
                .is_some_and(|layers| layers.contains_key(&Layer::Set));
            match without_setting(&text, name) {
                Some(rest) => {
                    text = rest;
                    removed.push((name.clone(), None));
                }
                None if set => {}
                None => bail!("`{name}` has no default in {} to forget", path.display()),
            }
        }
        // What the session alone held is forgotten without the file, which stays as it was
        if !removed.is_empty() {
            refuse_stray_edits(&path, &before, &text, &removed)?;
            write(&path, &text)?;
            self.mark_read();
        }
        for name in names {
            if let Some(layers) = self.values.get_mut(name) {
                layers.remove(&Layer::Set);
                layers.remove(&Layer::User);
                if layers.is_empty() {
                    self.values.remove(name);
                }
            }
        }
        log::info!("Forgot {} in {}", names.join(", "), path.display());
        Ok(())
    }

    /// The user's config file, where `--save` may write it: never the image's, which is
    /// written from the image's NixOS configuration and read-only, and never through a link,
    /// which would point at a file somebody else keeps
    fn writable_file(&self) -> Result<PathBuf> {
        let path = self.user_file().ok_or_else(|| {
            anyhow!(
                "There is no user config file without $XDG_CONFIG_HOME or $HOME; name one with \
                 --config"
            )
        })?;
        let image = Path::new(IMAGE_PATH);
        let canonical = |path: &Path| {
            path.parent()
                .and_then(|parent| parent.canonicalize().ok())
                .zip(path.file_name())
                .map(|(parent, name)| parent.join(name))
        };
        if path == image || canonical(path).is_some_and(|path| Some(path) == canonical(image)) {
            bail!(
                "{IMAGE_PATH} is the image's config, written from its NixOS configuration and \
                 read-only; --save writes the user's"
            );
        }
        if path.is_symlink() {
            bail!(
                "{} is a link, to a file kept elsewhere; --save writes a file of its own, so \
                 change the file it points at instead",
                path.display()
            );
        }
        // Written by renaming a new file over it, which its own mode would never stop
        if let Ok(metadata) = std::fs::metadata(path)
            && std::os::unix::fs::PermissionsExt::mode(&metadata.permissions()) & 0o200 == 0
        {
            bail!(
                "{} is read-only to its owner, so --save leaves it as it is; make it writable, \
                 `chmod u+w`, to let --save change it",
                path.display()
            );
        }
        Ok(path.to_path_buf())
    }

    /// Note that the user's file is there now, for a listing to say
    fn mark_read(&mut self) {
        if let Some(file) = self.files.iter_mut().find(|file| file.layer == Layer::User) {
            file.read = true;
        }
    }

    /// Each config file consulted, by its layer, and whether it was read
    pub(super) fn describe_files(&self) -> Vec<String> {
        self.files
            .iter()
            .map(|file| {
                let path = file.path.as_deref().map_or_else(
                    || "none, without $XDG_CONFIG_HOME or $HOME".into(),
                    |path| crate::common::printable(&path.display().to_string()),
                );
                let state = if file.read { "read" } else { "absent" };
                format!("{:<5}  {path} ({state})", file.layer.name())
            })
            .collect()
    }

    /// Each default in force as `name = value`, behind the layer it comes from
    ///
    /// A value is whatever a file or a `set` gave, so it is escaped for the terminal: a line
    /// break in a name must not draw a default of its own into the listing.
    pub(super) fn describe(&self) -> Vec<String> {
        self.values
            .keys()
            .filter_map(|name| {
                let (layer, value) = self.effective(name)?;
                let value = crate::common::printable(&value.to_string());
                Some(format!("{:<11}  {name} = {value}", layer.name()))
            })
            .collect()
    }

    /// Take in the environment's settings, as defaults over the files' ones, once at the
    /// start of a session
    pub(super) fn absorb_environment(&mut self) -> Result<()> {
        let command = super::command();
        for name in option_names(&command) {
            let variable = format!("MIND_THE_{}", name.to_uppercase().replace('-', "_"));
            let Some(value) = std::env::var_os(&variable) else {
                continue;
            };
            let value = value
                .into_string()
                .map_err(|_| anyhow!("{variable} is not valid UTF-8"))?;
            let value =
                parse_word(&name, &value, &command).with_context(|| format!("In {variable}"))?;
            self.values
                .entry(name)
                .or_default()
                .insert(Layer::Environment, value);
        }
        Ok(())
    }

    /// Make the defaults clap's own, on every verb that takes the option
    ///
    /// `env` keeps the settings' variables, which then win over the defaults; a session drops
    /// them, having taken them in once at the start, so that `set` is never undone by a
    /// variable read again on every line. The seeds' go too, being the session's own; the
    /// pins' stay, as they are no setting.
    pub(super) fn apply_to(&self, command: Command, env: bool) -> Command {
        let settings = option_names(&command);
        let apply = |arg: clap::Arg| -> clap::Arg {
            let session_owned = arg.get_long().is_some_and(|long| {
                settings.contains(long)
                    || [
                        "seed",
                        "password",
                        "card-seed",
                        "card-password",
                        "key-seed",
                        "key-password",
                    ]
                    .contains(&long)
            });
            let arg = if env || !session_owned {
                arg
            } else {
                arg.env(None)
            };
            // An applet's own defaults reach clap only through `for_app`
            let Some((_, value)) = arg.get_long().and_then(|long| self.effective(long)) else {
                return arg;
            };
            match value {
                Value::Text(text) => arg.default_value(text.clone()),
                Value::Flag(flag) => arg.default_value(flag.to_string()),
                Value::List(items) => arg.default_values(items.clone()),
            }
        };
        command
            .mut_args(apply)
            .mut_subcommands(|verb| verb.mut_args(apply))
    }

    /// Make the defaults clap's own, keeping the environment variables
    pub(super) fn apply(&self, command: Command) -> Command {
        self.apply_to(command, true)
    }
}

/// What a config file starts with when `--save` creates it
const HEADER: &str = "\
# mind-the-gap defaults: options by their long names, as `mind-the-gap set --help` lists them,
# with [piv] and [pgp] tables for one applet's own. `set --save` and `unset --save` write this
# file and keep everything else in it as it is.
";

/// The names `name=value` words set, for a message
fn names_of(settings: &[String]) -> String {
    settings
        .iter()
        .filter_map(|setting| setting.split_once('=').map(|(name, _)| name))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A config file's text to edit: what it holds, which has to read as a config file, or the
/// header of a new one
fn existing(path: &Path) -> Result<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            parse(&text).with_context(|| format!("In {}", path.display()))?;
            Ok(text)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(HEADER.into()),
        Err(err) => Err(anyhow!("Cannot read the config file {}: {err}", path.display())),
    }
}

/// Write a config file whole, in place of the one there: a new one readable by its owner
/// alone, as what it holds is a person's name and addresses, and one there with its mode
///
/// The text is read back first, as the next run would read it, so a file `--save` writes is
/// never one the next command refuses.
fn write(path: &Path, text: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

    let mut readback = Defaults::default();
    let command = super::command();
    for (key, value) in parse(text)? {
        readback
            .insert(&key, value.clone(), Layer::User)
            .and_then(|()| check(option_of(&key), &value, &command))
            .with_context(|| format!("{} would not read back", path.display()))?;
    }

    let directory = path.parent().unwrap_or(Path::new("."));
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)
        .with_context(|| format!("Cannot create {}", directory.display()))?;
    let mode = std::fs::metadata(path).map_or(0o600, |metadata| metadata.permissions().mode());
    let temporary = directory.join(format!(".config.toml.{}", std::process::id()));
    let written = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.set_permissions(std::fs::Permissions::from_mode(mode & 0o7777))?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        // Renamed over the file, so that a run interrupted half way leaves the old one whole
        std::fs::rename(&temporary, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written.with_context(|| format!("Cannot write the config file {}", path.display()))
}

/// The key a line of a config file sets, as `parse` reads it, in the table `table`
fn key_of_line(line: &str, table: Option<&str>) -> Option<String> {
    match Line::of(line) {
        Line::Setting(name, _) => key_in(table, name).ok(),
        _ => None,
    }
}

/// The table a line opens, where it is a header; a table `parse` refuses opens none
fn table_of_line(line: &str) -> Option<Option<&'static str>> {
    match Line::of(line) {
        Line::Table(table) => Some(table.ok()),
        _ => None,
    }
}

/// The defaults a config file's text holds, each key's last value, as reading it gives them
fn pairs_of(text: &str) -> Result<BTreeMap<String, Value>> {
    Ok(parse(text)?.into_iter().collect())
}

/// Refuse an edit of a config file that changed anything but `changed`: what the file holds
/// after it has to be what it held before, with `changed` set or, as none, taken out
fn refuse_stray_edits(
    path: &Path,
    before: &str,
    after: &str,
    changed: &[(String, Option<Value>)],
) -> Result<()> {
    let mut expected = pairs_of(before)?;
    for (key, value) in changed {
        match value {
            Some(value) => expected.insert(key.clone(), value.clone()),
            None => expected.remove(key),
        };
    }
    if pairs_of(after)? != expected {
        bail!(
            "Editing {} would change more than was asked, so it is left as it is; change it \
             by hand",
            path.display()
        );
    }
    Ok(())
}

/// A value as a config file spells it
fn rendered(value: &Value) -> String {
    // Every control character escaped, as TOML asks of a basic string: written raw, one
    // would make the file unreadable to another TOML reader
    let string = |text: &str| {
        let mut escaped = String::from('"');
        for ch in text.chars() {
            match ch {
                '\\' => escaped.push_str("\\\\"),
                '"' => escaped.push_str("\\\""),
                '\n' => escaped.push_str("\\n"),
                '\t' => escaped.push_str("\\t"),
                ch if ch.is_control() => escaped.push_str(&format!("\\u{:04X}", u32::from(ch))),
                ch => escaped.push(ch),
            }
        }
        escaped.push('"');
        escaped
    };
    match value {
        Value::Text(text) => string(text),
        Value::Flag(flag) => flag.to_string(),
        Value::List(items) => {
            let items: Vec<_> = items.iter().map(|item| string(item)).collect();
            format!("[{}]", items.join(", "))
        }
    }
}

/// A config file's text with `key` set to `value`
///
/// The line that sets it already takes the new value, its comment kept; a key set twice keeps
/// the first line and loses the others. A key not there yet goes after the last setting of its
/// table, `[piv]` and `[pgp]` added at the end where missing. Every other line stays as it is.
fn with_setting(text: &str, key: &str, value: &Value) -> String {
    let (table, name) = match key.split_once('.') {
        Some((table, name)) => (Some(table), name),
        None => (None, key),
    };
    let mut lines: Vec<String> = Vec::new();
    let mut current: Option<&str> = None;
    let mut replaced = false;
    // Where a new line goes: after the last line of the key's table that sets something, or
    // right after its header
    let mut anchor: Option<usize> = None;
    let mut first_header: Option<usize> = None;
    for line in text.lines() {
        if let Some(opened) = table_of_line(line) {
            current = opened;
            first_header.get_or_insert(lines.len());
            if current == table && table.is_some() {
                anchor = Some(lines.len() + 1);
            }
            lines.push(line.to_string());
            continue;
        }
        if key_of_line(line, current).as_deref() == Some(key) {
            if replaced {
                continue;
            }
            replaced = true;
            let comment = &line[strip_comment(line).len()..];
            let before = line.split_once('=').map_or(line, |(before, _)| before);
            let mut new = format!("{} = {}", before.trim_end(), rendered(value));
            if !comment.is_empty() {
                new = format!("{new} {}", comment.trim_start());
            }
            lines.push(new);
            continue;
        }
        if current == table && key_of_line(line, current).is_some() {
            anchor = Some(lines.len() + 1);
        }
        lines.push(line.to_string());
    }
    if !replaced {
        let new = format!("{name} = {}", rendered(value));
        match (table, anchor) {
            (_, Some(at)) => lines.insert(at, new),
            // A top-level key with none before it goes before the first table
            (None, None) => match first_header {
                Some(at) => {
                    lines.insert(at, String::new());
                    lines.insert(at, new);
                }
                None => lines.push(new),
            },
            (Some(table), None) => {
                if lines.last().is_some_and(|line| !line.trim().is_empty()) {
                    lines.push(String::new());
                }
                lines.push(format!("[{table}]"));
                lines.push(new);
            }
        }
    }
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

/// A config file's text without the lines that set `key`; none where no line does
fn without_setting(text: &str, key: &str) -> Option<String> {
    let mut lines = Vec::new();
    let mut current: Option<&str> = None;
    let mut removed = false;
    for line in text.lines() {
        if let Some(opened) = table_of_line(line) {
            current = opened;
        } else if key_of_line(line, current).as_deref() == Some(key) {
            removed = true;
            continue;
        }
        lines.push(line);
    }
    removed.then(|| {
        let mut text = lines.join("\n");
        text.push('\n');
        text
    })
}

/// Refuse a key no default takes: a secret, what belongs to one command, or no option at all
fn refuse_unfit_key(key: &str) -> Result<()> {
    let name = option_of(key);
    if SECRETS.contains(&name) {
        bail!("`{name}` is a secret, and secrets are never defaults; pass it per command");
    }
    if PER_COMMAND.contains(&name) {
        bail!("`{name}` belongs to one command and cannot be a default");
    }
    let command = super::command();
    if !option_names(&command).contains(name) {
        return Err(no_option(key, &command));
    }
    Ok(())
}

/// Whether a default's key names a secret, which no default holds
pub(super) fn is_secret(key: &str) -> bool {
    SECRETS.contains(&option_of(key))
}

/// The option a default's key names: the key itself, or behind an applet's table
fn option_of(key: &str) -> &str {
    key.strip_prefix("piv.")
        .or_else(|| key.strip_prefix("pgp."))
        .unwrap_or(key)
}

/// The table an applet's defaults go in, named as `--app` names the applet
fn table_of(app: App) -> &'static str {
    match app {
        App::Piv => "piv",
        App::Pgp => "pgp",
    }
}

/// Every option name a default may take: the long names of the options with an environment
/// variable, which is what makes an option a setting rather than an act, but for the secrets
/// and what belongs to one invocation
pub(super) fn option_names(command: &Command) -> std::collections::BTreeSet<String> {
    let mut names = std::collections::BTreeSet::new();
    let mut add = |command: &Command| {
        for arg in command.get_arguments() {
            if arg.get_env().is_some()
                && let Some(long) = arg.get_long()
                && !SECRETS.contains(&long)
                && !PER_COMMAND.contains(&long)
            {
                names.insert(long.to_string());
            }
        }
    };
    add(command);
    for verb in command.get_subcommands() {
        add(verb);
    }
    names
}

/// The names a default may take, grouped under the headings the options have in a verb's
/// help, or the verb whose own options they are, for `set --help` to list
pub(super) fn settable_names(command: &Command) -> String {
    let settable = option_names(command);
    let count = |verb: &Command| {
        verb.get_arguments()
            .filter(|arg| arg.get_long().is_some_and(|long| settable.contains(long)))
            .count()
    };
    // The verb that takes the most settings first, so that the groups come in the order its
    // help gives them
    let mut verbs: Vec<&Command> = command.get_subcommands().collect();
    verbs.sort_by_key(|verb| std::cmp::Reverse(count(verb)));
    let mut groups: Vec<(String, Vec<&str>)> = Vec::new();
    for verb in verbs {
        for arg in verb.get_arguments() {
            let Some(long) = arg.get_long().filter(|long| settable.contains(*long)) else {
                continue;
            };
            let group = arg
                .get_help_heading()
                .map_or_else(|| format!("`{}`", verb.get_name()), String::from);
            match groups.iter_mut().find(|(heading, _)| *heading == group) {
                Some((_, names)) if names.contains(&long) => {}
                Some((_, names)) => names.push(long),
                None => groups.push((group, vec![long])),
            }
        }
    }
    let width = groups
        .iter()
        .map(|(group, _)| group.len() + 1)
        .max()
        .unwrap_or(0);
    let mut text = String::from(
        "The names a default takes, each an option's long name, which is also its config file\n\
         key and, upper cased behind MIND_THE_, its variable:\n",
    );
    for (group, names) in groups {
        // Wrapped by hand: clap leaves the text after the help as it is
        let mut line = format!("  {:<width$}  ", format!("{group}:"));
        let indent = line.len();
        for (index, name) in names.iter().enumerate() {
            let item = if index + 1 < names.len() {
                format!("{name}, ")
            } else {
                name.to_string()
            };
            if line.len() + item.trim_end().len() > 92 {
                text.push_str(line.trim_end());
                text.push('\n');
                line = " ".repeat(indent);
            }
            line.push_str(&item);
        }
        text.push_str(&line);
        text.push('\n');
    }
    text.push_str(
        "Each takes `piv.` or `pgp.` before it for a default of that applet alone, as in\n\
         `set pgp.algorithm=rsa2048`.",
    );
    text
}

/// Why a key is no default: the setting it most likely means, behind the same applet's
/// table, or where the names are
fn no_option(key: &str, command: &Command) -> anyhow::Error {
    let name = option_of(key);
    let table = &key[..key.len() - name.len()];
    let names = option_names(command);
    // Close enough to be a typo of it: an edit or two, and fewer than half its letters
    let closest = names
        .iter()
        .map(|candidate| (edits(name, candidate), candidate))
        .filter(|(distance, _)| *distance <= 2 && *distance * 2 < name.len())
        .min();
    match closest {
        Some((_, close)) => anyhow!(
            "`{key}` is no option; the closest is `{table}{close}`, and `set --help` lists \
             them all"
        ),
        None => anyhow!("`{key}` is no option; `set --help` lists the names a default takes"),
    }
}

/// How many single letters are inserted, removed or replaced to turn one word into another
fn edits(from: &str, to: &str) -> usize {
    let to: Vec<char> = to.chars().collect();
    let mut row: Vec<usize> = (0..=to.len()).collect();
    for (i, a) in from.chars().enumerate() {
        let mut diagonal = row[0];
        row[0] = i + 1;
        for (j, b) in to.iter().enumerate() {
            let above = row[j + 1];
            row[j + 1] = (diagonal + usize::from(a != *b))
                .min(above + 1)
                .min(row[j] + 1);
            diagonal = above;
        }
    }
    row[to.len()]
}

/// A file's value, checked by the option's own parser as `set` checks a word
fn check(name: &str, value: &Value, command: &Command) -> Result<()> {
    let word = match value {
        Value::Text(text) => text.clone(),
        Value::Flag(flag) => flag.to_string(),
        Value::List(items) => items.join(","),
    };
    parse_word(name, &word, command).map(drop)
}

/// A `set` word's value, checked by the option's own parser
fn parse_word(name: &str, value: &str, command: &Command) -> Result<Value> {
    let arg = std::iter::once(command)
        .chain(command.get_subcommands())
        .flat_map(Command::get_arguments)
        .find(|arg| arg.get_long() == Some(name))
        .ok_or_else(|| no_option(name, command))?;
    let flag = matches!(arg.get_action(), clap::ArgAction::SetTrue);
    if flag {
        // One spelling each, as TOML spells them in a file
        return match value {
            "true" => Ok(Value::Flag(true)),
            "false" => Ok(Value::Flag(false)),
            _ => bail!("`{name}` is on or off: true or false"),
        };
    }
    let items: Vec<&str> = match arg.get_value_delimiter() {
        Some(delimiter) => value.split(delimiter).collect(),
        None => vec![value],
    };
    // The option's own parser, run on a command of that option alone
    let probe = Command::new("set")
        .no_binary_name(true)
        .arg(arg.clone().env(None).required(false).global(false));
    probe
        .try_get_matches_from([format!("--{name}={value}")])
        .map_err(|err| anyhow!("{}", err.to_string().trim_start_matches("error: ").trim()))?;
    Ok(match arg.get_value_delimiter() {
        Some(_) => Value::List(items.into_iter().map(String::from).collect()),
        None => Value::Text(value.to_string()),
    })
}

/// One line of a config file, as both the reader and the editor see it, so that the two
/// never disagree on which table a line is in or which key it sets
enum Line<'a> {
    /// Blank, or a comment alone
    Blank,
    /// A table header: `[piv]` or `[pgp]`, spaces inside the brackets or not, or another,
    /// which is refused
    Table(Result<&'static str, &'a str>),
    /// `name = value`, the name without its quotes and the value as written
    Setting(&'a str, &'a str),
    /// Anything else, which is refused
    Unknown,
}

impl Line<'_> {
    fn of(line: &str) -> Line<'_> {
        let line = strip_comment(line).trim();
        if line.is_empty() {
            return Line::Blank;
        }
        if let Some(header) = line.strip_prefix('[') {
            return Line::Table(match header.strip_suffix(']').map(str::trim) {
                Some("piv") => Ok("piv"),
                Some("pgp") => Ok("pgp"),
                other => Err(other.unwrap_or(header)),
            });
        }
        match line.split_once('=') {
            Some((name, value)) => Line::Setting(name.trim().trim_matches('"'), value.trim()),
            None => Line::Unknown,
        }
    }
}

/// The key a setting's name stands for in a table, `piv.<name>` or `pgp.<name>`, or at the top
/// level, where TOML's dotted keys spell the same
fn key_in(table: Option<&str>, name: &str) -> Result<String> {
    match table {
        Some(table) if name.contains('.') => {
            bail!("`{name}` in [{table}]: a table holds options alone")
        }
        Some(table) => Ok(format!("{table}.{name}")),
        None => Ok(name.to_string()),
    }
}

/// The `name = value` pairs of a TOML document, as far as a table of options goes: the
/// top level, and the `[piv]` and `[pgp]` tables, whose keys come back as `piv.<name>` and
/// `pgp.<name>`, as TOML's dotted keys spell them too
fn parse(text: &str) -> Result<Vec<(String, Value)>> {
    let mut pairs = Vec::new();
    let mut table: Option<&str> = None;
    for (index, line) in text.lines().enumerate() {
        let at = |err: anyhow::Error| err.context(format!("line {}", index + 1));
        match Line::of(line) {
            Line::Blank => {}
            Line::Table(Ok(name)) => table = Some(name),
            Line::Table(Err(_)) => {
                return Err(at(anyhow!(
                    "the only tables are [piv] and [pgp], each applet's own defaults"
                )));
            }
            Line::Setting(name, value) => {
                let key = key_in(table, name).map_err(at)?;
                pairs.push((key, parse_value(value).map_err(at)?));
            }
            Line::Unknown => return Err(at(anyhow!("expected `name = value`"))),
        }
    }
    Ok(pairs)
}

/// A line without its comment, which a `#` outside a string starts
fn strip_comment(line: &str) -> &str {
    let mut quoted = false;
    let mut escaped = false;
    for (index, ch) in line.char_indices() {
        match ch {
            '\\' if quoted => escaped = !escaped,
            '"' if !escaped => quoted = !quoted,
            '#' if !quoted => return &line[..index],
            _ => escaped = false,
        }
    }
    line
}

/// One TOML value: a basic string, a boolean, an integer or an array of strings
fn parse_value(text: &str) -> Result<Value> {
    match text {
        "true" => return Ok(Value::Flag(true)),
        "false" => return Ok(Value::Flag(false)),
        _ => {}
    }
    if text.parse::<i64>().is_ok() {
        return Ok(Value::Text(text.to_string()));
    }
    if let Some(inner) = text
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        let mut items = Vec::new();
        let mut rest = inner.trim();
        while !rest.is_empty() {
            let (item, after) = parse_string(rest)?;
            items.push(item);
            rest = after.trim_start();
            rest = rest.strip_prefix(',').unwrap_or(rest).trim_start();
        }
        return Ok(Value::List(items));
    }
    let (string, rest) = parse_string(text)?;
    if !rest.trim().is_empty() {
        bail!("unexpected `{}` after the value", rest.trim());
    }
    Ok(Value::Text(string))
}

/// A basic string at the start of `text`, and what follows it
fn parse_string(text: &str) -> Result<(String, &str)> {
    let rest = text.strip_prefix('"').ok_or_else(|| {
        anyhow!("expected a \"string\", true, false, a number or [\"a\", \"list\"]")
    })?;
    let mut out = String::new();
    let mut chars = rest.char_indices();
    while let Some((index, ch)) = chars.next() {
        match ch {
            '"' => return Ok((out, &rest[index + 1..])),
            '\\' => match chars.next().map(|(_, ch)| ch) {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('b') => out.push('\u{8}'),
                Some('f') => out.push('\u{c}'),
                Some(escape @ ('u' | 'U')) => {
                    let digits = if escape == 'u' { 4 } else { 8 };
                    let hex: String = chars.by_ref().take(digits).map(|(_, ch)| ch).collect();
                    let ch = u32::from_str_radix(&hex, 16)
                        .ok()
                        .filter(|_| {
                            hex.len() == digits && hex.chars().all(|ch| ch.is_ascii_hexdigit())
                        })
                        .and_then(char::from_u32)
                        .ok_or_else(|| anyhow!("\\{escape}{hex} is no character"))?;
                    out.push(ch);
                }
                other => bail!("unsupported escape \\{}", other.unwrap_or(' ')),
            },
            ch => out.push(ch),
        }
    }
    bail!("unterminated string")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flat_table_parses() {
        let pairs = parse(
            "# defaults\nname = \"Jane Doe\" # inline\nemails = [\"jane@example.com\", \"j@example.org\"]\nintermediate = true\n\nsubkey = \"laptop#1\"\n",
        )
        .unwrap();
        assert_eq!(
            pairs,
            vec![
                ("name".into(), Value::Text("Jane Doe".into())),
                (
                    "emails".into(),
                    Value::List(vec!["jane@example.com".into(), "j@example.org".into()])
                ),
                ("intermediate".into(), Value::Flag(true)),
                ("subkey".into(), Value::Text("laptop#1".into())),
            ]
        );
    }

    #[test]
    fn other_tables_and_garbage_are_refused() {
        assert!(parse("[cards]\nalgorithm = \"p384\"").is_err());
        assert!(parse("[piv]\npgp.algorithm = \"p256\"").is_err());
        assert!(parse("name = Jane").is_err());
        assert!(parse("name = \"Jane").is_err());
    }

    /// An applet's table holds its own defaults, the same as dotted keys, and each applet's
    /// half of a command sees the general defaults with its table over them
    #[test]
    fn applet_tables_override_for_their_applet_alone() {
        let pairs =
            parse("algorithm = \"p256\"\nsubkey = \"laptop\"\n[pgp]\nalgorithm = \"rsa2048\"\n")
                .unwrap();
        assert_eq!(pairs[2], ("pgp.algorithm".into(), Value::Text("rsa2048".into())));

        let mut defaults = Defaults::default();
        for (key, value) in pairs {
            defaults.insert(&key, value, Layer::User).unwrap();
        }
        defaults.set(&["piv.policy=strict".into()]).unwrap();
        assert!(defaults.has_tables());
        let pgp = defaults.for_app(App::Pgp);
        let piv = defaults.for_app(App::Piv);
        assert_eq!(*pgp.effective("algorithm").unwrap().1, Value::Text("rsa2048".into()));
        assert_eq!(*piv.effective("algorithm").unwrap().1, Value::Text("p256".into()));
        assert_eq!(*piv.effective("policy").unwrap().1, Value::Text("strict".into()));
        assert!(!pgp.values.contains_key("policy"));
        assert_eq!(pgp.effective("subkey"), piv.effective("subkey"));

        assert!(defaults.set(&["piv.algorithm=p385".into()]).is_err());
        assert!(defaults.set(&["piv.pin=123456".into()]).is_err());
        defaults.unset(&["piv.policy".into()]).unwrap();
        assert!(!defaults.for_app(App::Piv).values.contains_key("policy"));
    }

    /// A table counts within its own layer: `set` and the environment beat a file's `[piv]`
    /// value, and a file's table beats the same file's general value
    #[test]
    fn a_stronger_layer_beats_a_weaker_table() {
        let mut defaults = Defaults::default();
        for (key, value) in parse("algorithm = \"p256\"\n[piv]\nalgorithm = \"p384\"\n").unwrap() {
            defaults.insert(&key, value, Layer::User).unwrap();
        }
        let algorithm = |defaults: &Defaults| {
            defaults
                .for_app(App::Piv)
                .effective("algorithm")
                .unwrap()
                .1
                .clone()
        };
        assert_eq!(algorithm(&defaults), Value::Text("p384".into()));

        let mut environment = defaults.clone();
        environment
            .insert("algorithm", Value::Text("p256".into()), Layer::Environment)
            .unwrap();
        assert_eq!(algorithm(&environment), Value::Text("p256".into()));

        defaults.set(&["algorithm=p256".into()]).unwrap();
        assert_eq!(algorithm(&defaults), Value::Text("p256".into()));

        // The image's table does not beat the user's general value either
        let mut layered = Defaults::default();
        layered
            .insert("piv.algorithm", Value::Text("p384".into()), Layer::Image)
            .unwrap();
        layered
            .insert("algorithm", Value::Text("p256".into()), Layer::User)
            .unwrap();
        assert_eq!(algorithm(&layered), Value::Text("p256".into()));
    }

    /// `unset` forgets the value in force and goes back to the one beneath it
    #[test]
    fn unset_goes_back_a_layer() {
        let mut defaults = Defaults::default();
        defaults
            .insert("subkey", Value::Text("laptop".into()), Layer::User)
            .unwrap();
        defaults.set(&["subkey=desktop".into()]).unwrap();
        defaults.unset(&["subkey".into()]).unwrap();
        assert_eq!(*defaults.effective("subkey").unwrap().1, Value::Text("laptop".into()));
        defaults.unset(&["subkey".into()]).unwrap();
        assert!(defaults.effective("subkey").is_none());
        assert!(defaults.unset(&["subkey".into()]).is_err());
    }

    #[test]
    fn secrets_and_unknown_names_are_never_defaults() {
        let mut defaults = Defaults::default();
        assert!(
            defaults
                .insert("seed", Value::Text("x".into()), Layer::User)
                .is_err()
        );
        assert!(
            defaults
                .insert("pin", Value::Text("123456".into()), Layer::User)
                .is_err()
        );
        assert!(
            defaults
                .insert("yes", Value::Flag(true), Layer::User)
                .is_err()
        );
        assert!(
            defaults
                .insert("colour", Value::Text("x".into()), Layer::User)
                .is_err()
        );
        assert!(
            defaults
                .insert("subkey", Value::Text("laptop".into()), Layer::User)
                .is_ok()
        );
    }

    #[test]
    fn set_checks_values_with_the_options_parser() {
        let mut defaults = Defaults::default();
        assert!(defaults.set(&["policy=strict".into()]).is_ok());
        assert!(defaults.set(&["policy=strickt".into()]).is_err());
        assert!(defaults.set(&["date=2026-13-01".into()]).is_err());
        assert!(defaults.set(&["key=signature,decryption".into()]).is_ok());
        assert!(defaults.set(&["intermediate=true".into()]).is_ok());
        for other in ["yes", "no", "on", "1", "True"] {
            let err = defaults
                .set(&[format!("intermediate={other}")])
                .unwrap_err();
            assert!(format!("{err}").contains("true or false"), "{other}: {err}");
        }
        assert!(defaults.set(&["subkey".into()]).is_err());
    }

    /// `--save` edits a file line by line: a key's line takes the new value and keeps its
    /// comment, a new key goes after the last of its table, a missing table is added, and
    /// every other line stays as it was
    #[test]
    fn saving_keeps_the_rest_of_the_file() {
        let text =
            "# mine\nname = \"Old\" # who\n\n[pgp]\n# the gnuk\nalgorithm = \"curve25519\"\n";
        let text = with_setting(text, "name", &Value::Text("New \"Jr\"".into()));
        let text = with_setting(&text, "subkey", &Value::Text("laptop".into()));
        let text = with_setting(&text, "pgp.lang", &Value::List(vec!["de".into(), "en".into()]));
        let text = with_setting(&text, "piv.intermediate", &Value::Flag(true));
        assert_eq!(
            text,
            "# mine\nname = \"New \\\"Jr\\\"\" # who\nsubkey = \"laptop\"\n\n[pgp]\n# the gnuk\n\
             algorithm = \"curve25519\"\nlang = [\"de\", \"en\"]\n\n[piv]\nintermediate = true\n"
        );
        assert_eq!(parse(&text).unwrap()[0], ("name".into(), Value::Text("New \"Jr\"".into())));

        // A top-level key in a file of tables alone goes before the first table
        let text = with_setting("[pgp]\nalgorithm = \"rsa2048\"\n", "name", &Value::Flag(true));
        assert_eq!(text, "name = true\n\n[pgp]\nalgorithm = \"rsa2048\"\n");

        // A dotted key is the table's key, and a key set twice keeps one line
        let text = "pgp.algorithm = \"p256\"\nname = \"A\"\nname = \"B\"\n";
        let text = with_setting(text, "pgp.algorithm", &Value::Text("rsa2048".into()));
        let text = with_setting(&text, "name", &Value::Text("C".into()));
        assert_eq!(text, "pgp.algorithm = \"rsa2048\"\nname = \"C\"\n");

        assert_eq!(
            without_setting("name = \"A\"\n[pgp]\nalgorithm = \"x\"\n", "pgp.algorithm").unwrap(),
            "name = \"A\"\n[pgp]\n"
        );
        assert!(without_setting("name = \"A\"\n", "subkey").is_none());
        assert!(without_setting("[pgp]\nname = \"A\"\n", "name").is_none());
    }

    /// The image's config is the image's: `--save` never writes it, even where `--config`
    /// names it
    #[test]
    fn saving_never_writes_the_image_config() {
        let mut defaults = Defaults::default();
        defaults.files.push(ConfigFile {
            layer: Layer::User,
            path: Some(IMAGE_PATH.into()),
            read: true,
            named: true,
        });
        let err = defaults.save(&["name=Jane".into()]).unwrap_err();
        assert!(format!("{err:#}").contains("read-only"), "{err:#}");
        let err = defaults.unsave(&["name".into()]).unwrap_err();
        assert!(format!("{err:#}").contains("read-only"), "{err:#}");
    }

    /// The editor reads a file's tables and keys as the reader does, spaces inside a table's
    /// brackets and quoted names included, so an edit lands where the reader looks
    #[test]
    fn the_editor_reads_tables_as_the_reader_does() {
        let text = "name = \"A\"\n[ pgp ] # the gnuk\n\"algorithm\" = \"rsa2048\"\n";
        assert_eq!(pairs_of(text).unwrap().keys().collect::<Vec<_>>(), ["name", "pgp.algorithm"]);
        let edited = with_setting(text, "subkey", &Value::Text("laptop".into()));
        assert_eq!(pairs_of(&edited).unwrap()["subkey"], Value::Text("laptop".into()));
        assert_eq!(pairs_of(&edited).unwrap().len(), 3, "{edited}");

        let edited = with_setting(text, "algorithm", &Value::Text("p256".into()));
        let pairs = pairs_of(&edited).unwrap();
        assert_eq!(pairs["algorithm"], Value::Text("p256".into()), "{edited}");
        assert_eq!(pairs["pgp.algorithm"], Value::Text("rsa2048".into()), "{edited}");

        assert!(without_setting(text, "algorithm").is_none());
        let edited = without_setting(text, "pgp.algorithm").unwrap();
        assert_eq!(pairs_of(&edited).unwrap().len(), 1, "{edited}");
    }

    /// An edit that would change any default but the ones asked for is refused
    #[test]
    fn stray_edits_are_refused() {
        let path = Path::new("config.toml");
        let before = "name = \"A\"\nsubkey = \"x\"\n";
        let asked = [("name".to_string(), Some(Value::Text("B".into())))];
        assert!(refuse_stray_edits(path, before, "name = \"B\"\nsubkey = \"x\"\n", &asked).is_ok());
        assert!(refuse_stray_edits(path, before, "name = \"B\"\n", &asked).is_err());
        assert!(
            refuse_stray_edits(path, before, "name = \"B\"\nsubkey = \"y\"\n", &asked).is_err()
        );
        let forgot = [("subkey".to_string(), None)];
        assert!(refuse_stray_edits(path, before, "name = \"A\"\n", &forgot).is_ok());
    }

    /// Every control character is written escaped, as TOML asks, and read back as it was
    #[test]
    fn control_characters_are_written_escaped() {
        let text = "a\u{1}b\r\u{7f}\u{9b}\n\t\"\\ é";
        let line = rendered(&Value::Text(text.into()));
        assert_eq!(line, "\"a\\u0001b\\u000D\\u007F\\u009B\\n\\t\\\"\\\\ é\"");
        assert!(!line.chars().any(char::is_control), "{line:?}");
        assert_eq!(parse_value(&line).unwrap(), Value::Text(text.into()));
        assert_eq!(parse_value("\"\\U0001F600\"").unwrap(), Value::Text("😀".into()));
        for bad in ["\"\\u12\"", "\"\\u+123\"", "\"\\uD800\"", "\"\\uZZZZ\""] {
            assert!(parse_value(bad).is_err(), "{bad}");
        }
    }

    /// Every setting's variable is its long name behind MIND_THE_, upper-cased: one name
    /// for the flag, the default and the environment
    #[test]
    fn every_variable_is_named_after_its_option() {
        let command = super::super::command();
        for verb in std::iter::once(&command).chain(command.get_subcommands()) {
            for arg in verb.get_arguments() {
                let (Some(env), Some(long)) = (arg.get_env(), arg.get_long()) else {
                    continue;
                };
                let expected = format!("MIND_THE_{}", long.to_uppercase().replace('-', "_"));
                assert_eq!(
                    env.to_str(),
                    Some(expected.as_str()),
                    "--{long} of `{}`",
                    verb.get_name()
                );
            }
        }
    }
}
