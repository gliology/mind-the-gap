//! Build-time generator for the man pages and shell completions, run by the nix package, and
//! for the book's option reference, run by hand when the options change.

use std::io::Write;
use std::path::Path;

use clap::{Command, Parser};

use clap_complete::Shell;
use clap_mangen::Man;

/// Where the documentation site lives, linked from every man page
const DOCS_URL: &str = "https://gliology.github.io/mind-the-gap/";

/// Shells to generate completions for, and where each expects them
///
/// Spelled out rather than filtered from `Shell::value_variants`, so a shell clap adds later
/// is a deliberate decision here rather than something silently dropped.
const COMPLETIONS: [(Shell, &str); 3] = [
    (Shell::Bash, "share/bash-completion/completions"),
    (Shell::Fish, "share/fish/vendor_completions.d"),
    (Shell::Zsh, "share/zsh/vendor-completions"),
];

/// What clap's zsh script completes `run`'s recipe with, and what it completes it with here
const ZSH_RECIPE_SPEC: (&str, &str) = (
    "'::recipe -- The recipe to run (the file'\\''s first where omitted):_default'",
    "'::recipe -- The recipe to run (the file'\\''s first where omitted):_mind-the-gap_recipes'",
);

/// The recipe names a ceremony file defines, for each shell to complete `run` with
///
/// clap's completions are static, and the recipes are in a file the user writes, so each shell
/// reads them itself, from the file `run` would read: the one `--ceremony` names on the line,
/// else `MIND_THE_CEREMONY`, else a `ceremony` default at the top of the user's config file
/// (or the one `--config` or `MIND_THE_CONFIG` names), else the image's config's, else the
/// user's ceremony file, else the image's. A recipe is a name at the left margin before a
/// colon and a default a `ceremony = "..."` line before the first table, which is all a shell
/// needs of either grammar, and nothing is run to find them.
const BASH_RECIPES: &str = r#"
# A config file's `ceremony` default, from the lines before its first table
_mind__the__gap__config_ceremony() {
    [[ -r "$1" ]] && sed -n -e '/^[[:space:]]*\[/q' \
        -e 's/^[[:space:]]*"\{0,1\}ceremony"\{0,1\}[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
        "$1" | tail -n 1
}

# `run`'s recipes, from the ceremony file it would read
_mind__the__gap__recipes() {
    local file="" config="" value i
    for ((i = 1; i < COMP_CWORD; i++)); do
        # bash splits `--ceremony=FILE` into three words, the `=` one of them
        value="${COMP_WORDS[i + 1]}"
        [[ "$value" == "=" ]] && value="${COMP_WORDS[i + 2]}"
        case "${COMP_WORDS[i]}" in
            --ceremony) file="$value" ;;
            --config) config="$value" ;;
        esac
    done
    local home="${XDG_CONFIG_HOME:-$HOME/.config}/mind-the-gap"
    [[ -n "$file" ]] || file="${MIND_THE_CEREMONY:-}"
    [[ -n "$file" ]] ||
        file="$(_mind__the__gap__config_ceremony "${config:-${MIND_THE_CONFIG:-$home/config.toml}}")"
    [[ -n "$file" ]] || file="$(_mind__the__gap__config_ceremony /etc/mind-the-gap/config.toml)"
    if [[ -z "$file" ]]; then
        file="$home/ceremony"
        [[ -r "$file" ]] || file=/etc/mind-the-gap/ceremony
    fi
    [[ -r "$file" ]] && sed -n 's/^\([a-z0-9-][a-z0-9-]*\):.*/\1/p' "$file"
}

# clap's completion, with the recipes where `run` takes one: a word that is no option, after
# `run`, and no option's value
_mind__the__gap__with__recipes() {
    _mind__the__gap "$@"
    # The verb is the first word that is no option and no option's value; bash splits
    # `--key-seed=PHRASE` into three words, the `=` one of them
    local i verb=""
    for ((i = 1; i < COMP_CWORD; i++)); do
        case "${COMP_WORDS[i]}" in
            --config | --log-level | -s | --seed | -p | --password | --card-password | \
                --key-password)
                ((i++))
                [[ "${COMP_WORDS[i]}" == "=" ]] && ((i++))
                ;;
            =) ((i++)) ;;
            -*) ;;
            *) verb="${COMP_WORDS[i]}"; break ;;
        esac
    done
    case "$3" in
        --ceremony | --record | --log-level | --config | -s | --seed | -p | --password | \
            --card-password | --key-password) return 0 ;;
    esac
    if [[ "$verb" == run && "$2" != -* ]]; then
        COMPREPLY=($(compgen -W "$(_mind__the__gap__recipes)" -- "$2"))
    fi
}

if [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 4 || "${BASH_VERSINFO[0]}" -gt 4 ]]; then
    complete -F _mind__the__gap__with__recipes -o nosort -o bashdefault -o default mind-the-gap
else
    complete -F _mind__the__gap__with__recipes -o bashdefault -o default mind-the-gap
fi
"#;

/// The same for zsh, which clap's recipe spec calls
const ZSH_RECIPES: &str = r#"
# A config file's `ceremony` default, from the lines before its first table
(( $+functions[_mind-the-gap_config_ceremony] )) ||
_mind-the-gap_config_ceremony() {
    [[ -r $1 ]] && sed -n -e '/^[[:space:]]*\[/q' \
        -e 's/^[[:space:]]*"\{0,1\}ceremony"\{0,1\}[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
        $1 | tail -n 1
}

# `run`'s recipes, from the ceremony file it would read
(( $+functions[_mind-the-gap_recipes] )) ||
_mind-the-gap_recipes() {
    local file config i
    for (( i = 1; i < CURRENT; i++ )); do
        case $words[i] in
            --ceremony) file=$words[i+1] ;;
            --ceremony=*) file=${words[i]#--ceremony=} ;;
            --config) config=$words[i+1] ;;
            --config=*) config=${words[i]#--config=} ;;
        esac
    done
    local home=${XDG_CONFIG_HOME:-$HOME/.config}/mind-the-gap
    [[ -n $file ]] || file=${MIND_THE_CEREMONY:-}
    [[ -n $file ]] ||
        file=$(_mind-the-gap_config_ceremony ${config:-${MIND_THE_CONFIG:-$home/config.toml}})
    [[ -n $file ]] || file=$(_mind-the-gap_config_ceremony /etc/mind-the-gap/config.toml)
    if [[ -z $file ]]; then
        file=$home/ceremony
        [[ -r $file ]] || file=/etc/mind-the-gap/ceremony
    fi
    [[ -r $file ]] || return 1
    local -a recipes
    recipes=(${(f)"$(sed -n 's/^\([a-z0-9-][a-z0-9-]*\):.*/\1/p' $file)"})
    _describe -t recipes recipe recipes
}
"#;

/// The same for fish, as one more completion of `run`
const FISH_RECIPES: &str = r#"
# A config file's `ceremony` default, from the lines before its first table
function __fish_mind_the_gap_config_ceremony
    test -r $argv[1]; or return
    sed -n -e '/^[[:space:]]*\[/q' \
        -e 's/^[[:space:]]*"\{0,1\}ceremony"\{0,1\}[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
        $argv[1] | tail -n 1
end

# `run`'s recipes, from the ceremony file it would read
function __fish_mind_the_gap_recipes
    set -l words (commandline -opc)
    set -l file
    set -l config
    for i in (seq (count $words))
        set -l next (math $i + 1)
        switch $words[$i]
            case --ceremony
                set -q words[$next]; and set file $words[$next]
            case '--ceremony=*'
                set file (string replace -- '--ceremony=' '' $words[$i])
            case --config
                set -q words[$next]; and set config $words[$next]
            case '--config=*'
                set config (string replace -- '--config=' '' $words[$i])
        end
    end
    set -l home $HOME/.config
    set -q XDG_CONFIG_HOME; and test -n "$XDG_CONFIG_HOME"; and set home $XDG_CONFIG_HOME
    set home $home/mind-the-gap
    if test -z "$file"; and set -q MIND_THE_CEREMONY
        set file $MIND_THE_CEREMONY
    end
    if test -z "$config"
        set config $home/config.toml
        set -q MIND_THE_CONFIG; and set config $MIND_THE_CONFIG
    end
    test -n "$file"; or set file (__fish_mind_the_gap_config_ceremony $config)
    test -n "$file"; or set file (__fish_mind_the_gap_config_ceremony /etc/mind-the-gap/config.toml)
    if test -z "$file"
        set file $home/ceremony
        test -r $file; or set file /etc/mind-the-gap/ceremony
    end
    test -r $file; and string match -rg '^([a-z0-9-]+):' <$file
end
complete -c mind-the-gap -n "__fish_mind_the_gap_using_subcommand run" -f -a "(__fish_mind_the_gap_recipes)"
"#;

/// A shell's completion script with `run`'s recipes completed from the ceremony file
fn with_recipes(shell: Shell, script: String) -> String {
    match shell {
        Shell::Bash => script + BASH_RECIPES,
        Shell::Fish => script + FISH_RECIPES,
        Shell::Zsh => {
            let (spec, ours) = ZSH_RECIPE_SPEC;
            assert!(
                script.contains(spec),
                "clap's zsh script no longer completes the recipe as expected"
            );
            // Defined before the script's own last lines, which run the completion when the
            // file is autoloaded
            let (body, tail) = script
                .rsplit_once("if [ \"$funcstack[1]\" = \"_mind-the-gap\" ]")
                .expect("clap's zsh script ends by running the completion");
            format!(
                "{}{ZSH_RECIPES}\nif [ \"$funcstack[1]\" = \"_mind-the-gap\" ]{tail}",
                body.replace(spec, ours)
            )
        }
        other => unreachable!("no completions for {other}"),
    }
}

#[derive(Parser, Debug)]
#[command(author, version)]
struct OutputConfig {
    /// Prefix of output path of man page and completion
    #[arg(required_unless_present = "reference")]
    prefix: Option<std::path::PathBuf>,

    /// Write the book's option reference to this file instead
    #[arg(long, value_name = "FILE", conflicts_with = "prefix")]
    reference: Option<std::path::PathBuf>,
}

/// Whether a subcommand is worth a man page of its own
///
/// `help` is clap's built-in, and rendering it produces pages with an empty NAME and a
/// malformed header -- `mind-the-gap-help-help(1)` being the reductio. A hidden verb runs in
/// a session alone, which has `help` for it.
fn is_documented(cmd: &Command) -> bool {
    cmd.get_name() != "help" && !cmd.is_hide_set()
}

/// Write the man page for one command, cross-referencing the pages around it
fn generate_man_to(cmd: &Command, dir: &Path, related: &[String]) -> std::io::Result<()> {
    let name = cmd.get_display_name().unwrap_or_else(|| cmd.get_name());
    let mut file = std::fs::File::create(dir.join(format!("{name}.1")))?;

    // Hide rather than remove: `help` stays a working command, it just does not appear in the
    // rendered SUBCOMMANDS list, which would otherwise cross-reference a page we do not write.
    // Leaf commands have no `help` of their own, and `mut_subcommand` panics on a missing one.
    let documented = if cmd.get_subcommands().any(|sub| sub.get_name() == "help") {
        cmd.clone().mut_subcommand("help", |help| help.hide(true))
    } else {
        cmd.clone()
    };

    Man::new(documented).render(&mut file)?;

    // clap_mangen renders no SEE ALSO, and roff is append-only, so add one here rather than
    // reimplementing the rest of the page
    if !related.is_empty() {
        let refs: Vec<String> = related
            .iter()
            .map(|entry| format!("\\fB{entry}\\fR(1)"))
            .collect();

        writeln!(file, ".SH SEE ALSO")?;
        writeln!(file, "{}", refs.join(", "))?;
    }

    writeln!(file, ".PP")?;
    writeln!(file, "Full documentation at \\fI{DOCS_URL}\\fR")?;

    Ok(())
}

fn main() -> std::io::Result<()> {
    // Parse command line
    let OutputConfig { prefix, reference } = OutputConfig::parse();
    if let Some(file) = reference {
        println!("Exporting the option reference to '{}'...", file.display());
        return std::fs::write(file, mind_the_gap::cli::reference());
    }
    let prefix = prefix.expect("required without --reference");

    // Build command line interface
    let mut cmd = mind_the_gap::cli::command();
    cmd.build();

    // Export manpage for ...
    let mandir = prefix.join("share/man/man1");

    println!("Exporting manpage to '{}'...", mandir.display());

    std::fs::create_dir_all(&mandir)?;

    let display = |cmd: &Command| {
        cmd.get_display_name()
            .unwrap_or_else(|| cmd.get_name())
            .to_string()
    };

    let root = display(&cmd);
    let verbs: Vec<String> = cmd
        .get_subcommands()
        .filter(|c| is_documented(c))
        .map(display)
        .collect();

    // - Main executable, pointing at each verb ...
    generate_man_to(&cmd, &mandir, &verbs)?;

    // - ... and each verb, which points back up
    for verb in cmd.get_subcommands().filter(|c| is_documented(c)) {
        generate_man_to(verb, &mandir, std::slice::from_ref(&root))?;
    }

    // Export shell completions
    let name = cmd.get_name().to_string();

    for (shell, suffix) in COMPLETIONS {
        let compdir = prefix.join(suffix);

        println!("Exporting completion to '{}'...", compdir.display());

        std::fs::create_dir_all(&compdir)?;
        let mut script = Vec::new();
        clap_complete::generate(shell, &mut cmd, &name, &mut script);
        let script = String::from_utf8(script).expect("clap writes UTF-8");
        let file = clap_complete::Generator::file_name(&shell, &name);
        std::fs::write(compdir.join(file), with_recipes(shell, script))?;
    }

    Ok(())
}
