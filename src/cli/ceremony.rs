//! Ceremonies: named recipes of commands, run in order with what they depend on.
//!
//! A ceremony file is laid out like a justfile. A recipe starts at the left margin with its
//! name and, after a colon, the recipes that run before it; its steps follow, indented, one
//! command line each, exactly as a session takes them. Comments start with `#`. The first
//! recipe is the one `run` runs without a name.
//!
//! ```text
//! # Personal card, one seed
//! card: init keys
//!
//! init:
//!     init --policy relaxed
//!
//! keys:
//!     upload
//!     publish --to certs/
//! ```
//!
//! Every step is shown before it runs, a failing one stops the ceremony, and `--dry-run`
//! shows the steps and what the writing ones would write. A file holds no secret: the seeds
//! and pins are asked for, or come from the environment.

use super::session::{Flow, Session, names_a_secret, takes_dry_run};

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use anyhow::{Context, Result, anyhow, bail};

use sha2::{Digest, Sha256};

/// The ceremony file of the live image, written from its NixOS configuration and read-only
pub(super) const IMAGE_PATH: &str = "/etc/mind-the-gap/ceremony";

/// The user's ceremony file: `$XDG_CONFIG_HOME/mind-the-gap/ceremony`
fn user_path() -> Option<PathBuf> {
    super::config::user_path().map(|config| config.with_file_name("ceremony"))
}

/// The image's ceremony, where this runs on the image
pub(super) fn image_default() -> Option<PathBuf> {
    Some(PathBuf::from(IMAGE_PATH)).filter(|path| path.exists())
}

/// One recipe: its name, the recipes it depends on, and its steps with their line numbers
#[derive(Clone, Debug, PartialEq, Eq)]
struct Recipe {
    name: String,
    dependencies: Vec<String>,
    steps: Vec<(usize, String)>,
}

/// A line without its comment: `#` starts one where a shell word would start, outside quotes,
/// so that `-n "Team #1"` keeps its name
fn strip_comment(line: &str) -> &str {
    let (mut single, mut double, mut escaped) = (false, false, false);
    let mut previous = ' ';
    for (at, c) in line.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if !single => escaped = true,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '#' if !single && !double && previous.is_whitespace() => return &line[..at],
            _ => {}
        }
        previous = c;
    }
    line
}

/// Refuse steps no ceremony may hold: another ceremony's run, or a secret
///
/// Refused as a whole before anything is shown, recorded or run, and without the line,
/// which would put the secret on the terminal and into the transcript.
fn refuse_unfit_steps(steps: &[(&str, usize, &str)]) -> Result<()> {
    for (recipe, line, step) in steps {
        let words = shlex::split(step).unwrap_or_default();
        if words.first().map(String::as_str) == Some("run") {
            bail!("A step cannot run another ceremony; list the recipe as a dependency instead");
        }
        // A ceremony's settings last as long as it does, and a dry run runs its `set` steps
        if matches!(words.first().map(String::as_str), Some("set" | "unset"))
            && words.iter().any(|word| word == "--save")
        {
            bail!(
                "Line {line} of the ceremony (recipe `{recipe}`) saves defaults; a ceremony's \
                 settings last as long as it does, and the config file is the user's to write"
            );
        }
        if let Some(secret) = names_a_secret(&words, true) {
            bail!(
                "{secret} is written in line {line} of the ceremony (recipe `{recipe}`); a \
                 ceremony never holds one, it is asked for or comes from the environment"
            );
        }
    }
    Ok(())
}

/// A parsed ceremony file
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Ceremony {
    recipes: Vec<Recipe>,
}

impl Ceremony {
    /// Parse a ceremony file's text
    fn parse(text: &str) -> Result<Ceremony> {
        let mut recipes: Vec<Recipe> = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let number = index + 1;
            let line = strip_comment(line);
            let content = line.trim();
            if content.is_empty() || content.starts_with('#') {
                continue;
            }
            if line.starts_with(char::is_whitespace) {
                let recipe = recipes
                    .last_mut()
                    .ok_or_else(|| anyhow!("line {number}: a step before any recipe"))?;
                recipe.steps.push((number, content.to_string()));
                continue;
            }
            let (name, dependencies) = content
                .split_once(':')
                .ok_or_else(|| anyhow!("line {number}: expected `recipe: dependencies`"))?;
            let name = name.trim();
            if name.is_empty()
                || !name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                bail!("line {number}: a recipe is named in lowercase letters, digits and hyphens");
            }
            if recipes.iter().any(|recipe| recipe.name == name) {
                bail!("line {number}: recipe `{name}` is defined twice");
            }
            recipes.push(Recipe {
                name: name.to_string(),
                dependencies: dependencies.split_whitespace().map(String::from).collect(),
                steps: Vec::new(),
            });
        }
        for recipe in &recipes {
            for dependency in &recipe.dependencies {
                if !recipes.iter().any(|other| &other.name == dependency) {
                    bail!(
                        "recipe `{}` depends on `{dependency}`, which is not defined",
                        recipe.name
                    );
                }
            }
        }
        Ok(Ceremony { recipes })
    }

    /// Every recipe with the recipes it depends on, as `run --check` lists them first:
    /// `card (init keys), init, keys (init)`
    fn summary(&self) -> String {
        let recipes: Vec<_> = self
            .recipes
            .iter()
            .map(|recipe| match recipe.dependencies.as_slice() {
                [] => recipe.name.clone(),
                dependencies => format!("{} ({})", recipe.name, dependencies.join(" ")),
            })
            .collect();
        recipes.join(", ")
    }

    /// The steps of `recipe` and of everything it depends on, each recipe once, dependencies
    /// first in the order they are listed
    fn plan(&self, recipe: Option<&str>) -> Result<Vec<(&str, usize, &str)>> {
        let first = self
            .recipes
            .first()
            .ok_or_else(|| anyhow!("The ceremony has no recipe"))?;
        let name = recipe.unwrap_or(&first.name);
        // The dependencies were checked when the file was read, so only the recipe asked for
        // can be missing, and the file's own recipes are the way out
        if !self.recipes.iter().any(|recipe| recipe.name == name) {
            let names: Vec<_> = self
                .recipes
                .iter()
                .map(|recipe| recipe.name.as_str())
                .collect();
            bail!("The ceremony has no recipe `{name}`; it has {}", names.join(", "));
        }
        let mut order: Vec<&Recipe> = Vec::new();
        let mut visiting: Vec<&str> = Vec::new();
        self.visit(name, &mut order, &mut visiting)?;
        Ok(order
            .into_iter()
            .flat_map(|recipe| {
                recipe
                    .steps
                    .iter()
                    .map(move |(line, step)| (recipe.name.as_str(), *line, step.as_str()))
            })
            .collect())
    }

    fn visit<'a>(
        &'a self,
        name: &str,
        order: &mut Vec<&'a Recipe>,
        visiting: &mut Vec<&'a str>,
    ) -> Result<()> {
        let recipe = self
            .recipes
            .iter()
            .find(|recipe| recipe.name == name)
            .ok_or_else(|| anyhow!("The ceremony has no recipe `{name}`"))?;
        if order.iter().any(|done| done.name == name) {
            return Ok(());
        }
        if visiting.contains(&recipe.name.as_str()) {
            bail!("Recipe `{name}` depends on itself: {} -> {name}", visiting.join(" -> "));
        }
        visiting.push(&recipe.name);
        for dependency in &recipe.dependencies {
            self.visit(dependency, order, visiting)?;
        }
        visiting.pop();
        order.push(recipe);
        Ok(())
    }
}

/// Run a ceremony in `session`: `recipe` from `file`, or the default one
pub(super) fn run(
    session: &mut Session,
    recipe: Option<&str>,
    file: Option<&Path>,
    record: Option<&Path>,
    dry_run: bool,
    check: bool,
) -> Result<()> {
    let path = match file {
        Some(path) => path.to_path_buf(),
        None => user_path()
            .filter(|path| path.exists())
            .or_else(image_default)
            .ok_or_else(|| {
                anyhow!(
                    "No ceremony file: pass --ceremony, or write one at {}",
                    user_path()
                        .map_or_else(|| IMAGE_PATH.into(), |path| path.display().to_string())
                )
            })?,
    };
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("Cannot read the ceremony {}", path.display()))?;
    let ceremony =
        Ceremony::parse(&text).with_context(|| format!("In the ceremony {}", path.display()))?;
    let steps = ceremony.plan(recipe)?;
    refuse_unfit_steps(&steps)?;

    // Every recipe, not only the one asked for, so that a file passes or fails as a whole:
    // what the image ships is checked when it is built
    if check {
        for other in &ceremony.recipes {
            refuse_unfit_steps(&ceremony.plan(Some(&other.name))?)?;
        }
        println!("Recipes: {}", ceremony.summary());
        for (index, (recipe, _, step)) in steps.iter().enumerate() {
            println!("[{}/{}] {recipe}: {step}", index + 1, steps.len());
        }
        return Ok(());
    }

    if let Some(directory) = record {
        Transcript::start(
            directory,
            &path,
            &text,
            // The recipe asked for, which without a name is the file's first, not the first
            // one to run
            recipe.unwrap_or(
                ceremony
                    .recipes
                    .first()
                    .map_or("", |first| first.name.as_str()),
            ),
        )?;
    }

    // The ceremony's own `set`s last as long as it does
    let defaults = session.defaults.clone();
    let result = (|| {
        for (index, (recipe, line, step)) in steps.iter().enumerate() {
            let verb = shlex::split(step)
                .and_then(|words| words.first().cloned())
                .unwrap_or_default();
            let shown = format!("[{}/{}] {recipe}: {step}", index + 1, steps.len());
            eprintln!("==> {shown}");
            transcribe(&format!("step {shown}"));
            let given = shlex::split(step).unwrap_or_default();
            let line_text = if dry_run && takes_dry_run(&verb) {
                if given.iter().any(|word| word == "--dry-run") {
                    step.to_string()
                } else {
                    format!("{step} --dry-run")
                }
            } else if dry_run && !matches!(verb.as_str(), "set" | "unset" | "list" | "check") {
                eprintln!("    (not run in a dry run)");
                continue;
            } else {
                step.to_string()
            };
            match session.run_line(&line_text, true) {
                Ok(Flow::Continue) => transcribe("done"),
                Ok(Flow::Quit) => {
                    transcribe("quit");
                    return Ok(());
                }
                Err(err) => {
                    transcribe(&format!("failed: {err:#}"));
                    return Err(err.context(format!(
                        "Step {} of the ceremony failed, at {}:{line}; nothing after it ran",
                        index + 1,
                        path.display()
                    )));
                }
            }
        }
        Ok(())
    })();
    session.defaults = defaults;
    transcribe(match &result {
        Ok(()) => "ceremony finished",
        Err(_) => "ceremony stopped",
    });
    Transcript::stop();
    result
}

/// The transcript of a ceremony being recorded
static TRANSCRIPT: Mutex<Option<File>> = Mutex::new(None);

struct Transcript;

impl Transcript {
    /// Start a transcript in `directory`, named by the time it starts
    fn start(directory: &Path, path: &Path, text: &str, recipe: &str) -> Result<()> {
        std::fs::create_dir_all(directory)?;
        let started = humantime::format_rfc3339_seconds(SystemTime::now()).to_string();
        let file_name = format!("ceremony-{}.log", started.replace(':', ""));
        let mut file = File::create(directory.join(&file_name))?;
        writeln!(file, "{} {}", env!("CARGO_PKG_NAME"), super::version())?;
        writeln!(file, "started {started}")?;
        writeln!(file, "ceremony {} sha256:{:x}", path.display(), Sha256::digest(text))?;
        writeln!(file, "recipe {recipe}")?;
        *TRANSCRIPT.lock().expect("never poisoned") = Some(file);
        log::info!("Recording the ceremony in {}", directory.join(file_name).display());
        Ok(())
    }

    fn stop() {
        *TRANSCRIPT.lock().expect("never poisoned") = None;
    }
}

/// Add a line to the transcript, where one is being recorded
///
/// The log goes here too, line by line: it never holds a secret, which is the rule that makes
/// a log safe to keep, and so it is safe to keep in a ceremony's record.
pub(super) fn transcribe(line: &str) {
    if let Ok(mut guard) = TRANSCRIPT.lock()
        && let Some(file) = guard.as_mut()
    {
        let now = humantime::format_rfc3339_seconds(SystemTime::now());
        let _ = writeln!(file, "{now} {line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "\
# A personal card
card: init keys

init:
    init --policy relaxed

keys: init
    upload
    publish --to certs/

publish:
    publish --format wkd --to wkd/
";

    #[test]
    fn recipes_run_after_their_dependencies_and_once() {
        let ceremony = Ceremony::parse(FILE).unwrap();
        let steps: Vec<_> = ceremony
            .plan(None)
            .unwrap()
            .into_iter()
            .map(|(recipe, _, step)| format!("{recipe}: {step}"))
            .collect();
        assert_eq!(
            steps,
            [
                "init: init --policy relaxed",
                "keys: upload",
                "keys: publish --to certs/"
            ]
        );
        assert_eq!(ceremony.plan(Some("publish")).unwrap().len(), 1);
        let missing = ceremony.plan(Some("nothing")).unwrap_err().to_string();
        assert!(missing.ends_with("it has card, init, keys, publish"), "{missing}");
        assert_eq!(ceremony.summary(), "card (init keys), init, keys (init), publish");
    }

    /// `#` starts a comment where a shell word would, and stays inside quotes and words
    #[test]
    fn comments_end_a_line() {
        let ceremony = Ceremony::parse(
            "a: b # the dependency\n    publish -n \"Team #1\" -k x#y # why\n    # a step left out\nb:\n    list\n",
        )
        .unwrap();
        let steps: Vec<_> = ceremony
            .plan(Some("a"))
            .unwrap()
            .into_iter()
            .map(|(_, _, step)| step)
            .collect();
        assert_eq!(steps, ["list", "publish -n \"Team #1\" -k x#y"]);
    }

    #[test]
    fn cycles_and_unknown_dependencies_are_refused() {
        let cyclic = Ceremony::parse("a: b\n    list\nb: a\n    list\n").unwrap();
        assert!(cyclic.plan(None).is_err());
        assert!(Ceremony::parse("a: missing\n    list\n").is_err());
        assert!(Ceremony::parse("    list\n").is_err());
        assert!(Ceremony::parse("Bad Name:\n").is_err());
        assert!(Ceremony::parse("a:\na:\n").is_err());
    }
}
