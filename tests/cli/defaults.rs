//! Defaults: `set` and `unset` in a session, the environment, config files and their applet
//! tables.

use crate::{
    TEST_PHRASE, WHO, bin, carried_on, listed, repl, repl_with, root_pem, root_subject, seeded,
    stderr, stdout,
};

use std::process::Command;

/// `set` stores defaults under the options' long names, shows them alone, and `unset`
/// forgets them; values are checked by the option's own parser, and neither secrets nor
/// what belongs to one command can become a default.
#[test]
fn set_and_unset_manage_the_session_defaults() {
    let script = "set name=Jane subkey=laptop
set
set policy=strickt
set date=2026-13-01
set seed=x
set pin=123456
set yes=true
set colour=red
set subkey
unset name subkey
unset name
set
quit
";
    let out = repl(script, &[]);
    let (out_text, err) = (stdout(&out), stderr(&out));

    carried_on(&out, 8);
    assert!(listed(&out_text, "set", "name = Jane"), "set did not store the name:\n{out_text}");
    assert!(listed(&out_text, "set", "subkey = laptop"), "set did not store both:\n{out_text}");
    assert!(err.contains("invalid value 'strickt'"), "a bad policy was stored:\n{err}");
    assert!(err.contains("2026-13-01"), "a bad date was stored:\n{err}");
    assert!(err.contains("`seed` is a secret"), "the seed became a default:\n{err}");
    assert!(err.contains("`pin` is a secret"), "a pin became a default:\n{err}");
    assert!(err.contains("`yes` belongs to one command"), "--yes became a default:\n{err}");
    assert!(err.contains("`colour` is no option"), "an unknown name was stored:\n{err}");
    assert!(err.contains("is not name=value"), "a bare name was stored:\n{err}");
    assert!(err.contains("`name` has no default to forget"), "unset forgot twice:\n{err}");
    assert!(out_text.contains("no defaults set"), "unset left a default:\n{out_text}");
}

/// A stored default applies to every later line, and a line's own option wins over it.
#[test]
fn set_defaults_apply_and_lines_win() {
    let dir = tempfile::tempdir().unwrap();
    let [stored, own] = ["stored.pem", "own.pem"].map(|name| dir.path().join(name));
    let script = format!(
        "set name=Jane
publish --app piv --part identity --to {stored}
publish --app piv --part identity -n Bob --to {own}
quit
",
        stored = stored.display(),
        own = own.display()
    );

    let out = repl(&script, &["-s", TEST_PHRASE]);
    assert!(out.status.success(), "session died: {:?}", out);
    assert_eq!(root_subject(&std::fs::read(stored).unwrap()), "CN=Jane PIV Root CA p256");
    assert_eq!(root_subject(&std::fs::read(own).unwrap()), "CN=Bob PIV Root CA p256");
}

/// `unset` forgets a stored default: afterwards the session derives as if never `set`.
#[test]
fn unset_forgets_a_stored_default() {
    let dir = tempfile::tempdir().unwrap();
    let [set, unset] = ["set.pem", "unset.pem"].map(|name| dir.path().join(name));
    let script = format!(
        "set identity-date=2026-01-01
publish --app piv --part identity -n Jane --to {set}
unset identity-date
publish --app piv --part identity -n Jane --to {unset}
quit
",
        set = set.display(),
        unset = unset.display()
    );
    let out = repl(&script, &["-s", TEST_PHRASE]);
    assert!(out.status.success(), "session died: {:?}", out);

    let plain = root_pem(bin(), &["-n", "Jane"]);
    let [set, unset] = [set, unset].map(|path| std::fs::read(path).unwrap());
    assert_ne!(set, unset, "the stored date did not apply before unset");
    assert_eq!(unset, plain, "unset did not restore the default");
}

/// The session takes the environment's settings in once, as defaults it shows and `set`
/// can change.
#[test]
fn a_session_takes_the_environment_in_once() {
    let mut cmd = bin();
    cmd.env("MIND_THE_SUBKEY", "laptop");
    let out = repl_with(cmd, "set\nset subkey=phone\nset\nquit\n", &[]);
    let text = stdout(&out);

    assert!(out.status.success(), "session died: {:?}", out);
    assert!(listed(&text, "environment", "subkey = laptop"), "the variable was not taken:\n{text}");
    assert!(listed(&text, "set", "subkey = phone"), "set did not win over the variable:\n{text}");
}

/// `set` alone shows the defaults on the command line too, as the session does: the config
/// files consulted first, each by its layer and whether it was read, then every default behind
/// the layer it comes from. Anything else `set` and `unset` would change is refused there.
#[test]
fn set_alone_shows_the_files_and_layers() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("mind-the-gap").join("config.toml");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(&config, "name = \"Jane Doe\"\n[pgp]\nalgorithm = \"rsa2048\"\n").unwrap();

    let mut cmd = bin();
    cmd.env("XDG_CONFIG_HOME", dir.path())
        .env("MIND_THE_SUBKEY", "laptop");
    let out = cmd.arg("set").output().unwrap();
    let text = stdout(&out);
    assert!(out.status.success(), "set alone failed:\n{}", stderr(&out));
    let user = format!("{} (read)", config.display());
    assert!(listed(&text, "user", &user), "the user's file is not named:\n{text}");
    assert!(
        listed(&text, "image", "/etc/mind-the-gap/config.toml (absent)")
            || listed(&text, "image", "/etc/mind-the-gap/config.toml (read)"),
        "the image's file is not named:\n{text}"
    );
    assert!(listed(&text, "user", "name = Jane Doe"), "{text}");
    assert!(listed(&text, "user", "pgp.algorithm = rsa2048"), "{text}");
    assert!(listed(&text, "environment", "subkey = laptop"), "{text}");
    assert!(text.contains("not given"), "a one-shot run claims it would ask:\n{text}");
    // The path is said once, in the header, not on every default
    assert_eq!(text.matches(&*config.display().to_string()).count(), 1, "{text}");

    // A file named with --config is the user's layer; an absent user's file says so
    let mut cmd = bin();
    cmd.args(["--config", config.to_str().unwrap(), "set"]);
    assert!(listed(&stdout(&cmd.output().unwrap()), "user", &user));
    let text = stdout(&bin().arg("set").output().unwrap());
    assert!(
        listed(&text, "user", "/nonexistent/mind-the-gap-tests/mind-the-gap/config.toml (absent)"),
        "{text}"
    );

    for args in [&["set", "name=Jane"][..], &["unset", "name"]] {
        let out = bin().args(args).output().unwrap();
        assert!(!out.status.success(), "{args:?} ran as a one-shot command");
        assert!(stderr(&out).contains("--save"), "{args:?}: {}", stderr(&out));
        assert!(stderr(&out).contains("config"), "{args:?}: {}", stderr(&out));
    }
    let out = bin().arg("quit").output().unwrap();
    assert!(!out.status.success(), "quit ran as a one-shot command");
    assert!(stderr(&out).contains("leaves a session"), "{}", stderr(&out));
}

/// A default's value is whatever a file, a variable or a `set` gave, so the listing escapes
/// it: a line break in a name cannot draw a default of its own into what `set` shows.
#[test]
fn the_listing_escapes_what_it_shows() {
    let mut cmd = bin();
    cmd.env("MIND_THE_NAME", "Jane\n  image        evil = INJECTED\u{1b}[2J");
    let text = stdout(&cmd.arg("set").output().unwrap());
    assert!(!listed(&text, "image", "evil = INJECTED"), "a forged line:\n{text}");
    assert!(!text.contains('\u{1b}'), "an escape reached the terminal:\n{text}");
    assert!(text.contains("name = Jane\\u{a}  image"), "{text}");
}

/// Defaults come from the config file, and a variable and then a flag win over it.
#[test]
fn config_file_defaults_and_precedence() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("mind-the-gap").join("config.toml");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(
        &config,
        "# defaults\nname = \"Config\" # the cardholder\nintermediate = false\n",
    )
    .unwrap();

    let subject = |cmd: Command, args: &[&str]| root_subject(&root_pem(cmd, args));

    let mut from_xdg = bin();
    from_xdg.env("XDG_CONFIG_HOME", dir.path());
    assert_eq!(subject(from_xdg, &[]), "CN=Config PIV Root CA p256");

    let mut from_flag = bin();
    from_flag.args(["--config", config.to_str().unwrap()]);
    assert_eq!(subject(from_flag, &[]), "CN=Config PIV Root CA p256");

    let mut env_wins = bin();
    env_wins
        .env("XDG_CONFIG_HOME", dir.path())
        .env("MIND_THE_NAME", "Env");
    assert_eq!(subject(env_wins, &[]), "CN=Env PIV Root CA p256");

    let mut flag_wins = bin();
    flag_wins
        .env("XDG_CONFIG_HOME", dir.path())
        .env("MIND_THE_NAME", "Env");
    assert_eq!(subject(flag_wins, &["-n", "Flag"]), "CN=Flag PIV Root CA p256");
}

/// A config file holds options, at the top level or in an applet's table, and nothing else.
#[test]
fn config_files_refuse_what_is_no_default() {
    let dir = tempfile::tempdir().unwrap();
    for (content, complaint) in [
        ("[cards]\nalgorithm = \"p384\"\n", "the only tables are [piv] and [pgp]"),
        ("[pgp]\npin = \"123456\"\n", "`pin` is a secret"),
        ("colour = \"red\"\n", "`colour` is no option"),
        ("seed = \"abandon\"\n", "`seed` is a secret"),
        ("pin = \"123456\"\n", "`pin` is a secret"),
        ("yes = true\n", "belongs to one command"),
        ("name = Jane\n", "expected a \"string\""),
        // A value is checked by its option's parser when the file is read, naming the file
        ("[piv]\npolicy = \"strickt\"\n", "config.toml"),
        ("date = \"2026-13-01\"\n", "config.toml"),
    ] {
        let path = dir.path().join("config.toml");
        std::fs::write(&path, content).unwrap();
        let out = bin()
            .args(["--config", path.to_str().unwrap(), "publish"])
            .output()
            .unwrap();
        let err = stderr(&out);
        assert!(!out.status.success(), "{content:?} was accepted");
        assert!(err.contains(complaint), "{content:?} refused for another reason:\n{err}");
    }
}

/// An applet's table holds defaults for that applet's half of a command alone: the same
/// command derives OpenPGP as the table says and PIV as before, and a flag beats the table
#[test]
fn applet_tables_reach_their_applet_alone() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "[pgp]\nalgorithm = \"rsa2048\"\n").unwrap();
    let publish = |extra: &[&str], app: &str| {
        let out = seeded(&[&["publish", "--app", app, "--to", "-"][..], &WHO, extra].concat());
        assert!(out.status.success(), "{}", stderr(&out));
        out.stdout
    };
    let with_table = |extra: &[&str], app: &str| {
        publish(&[&["--config", config.to_str().unwrap()][..], extra].concat(), app)
    };
    assert_eq!(with_table(&[], "pgp"), publish(&["--algorithm", "rsa2048"], "pgp"));
    assert_eq!(with_table(&[], "piv"), publish(&[], "piv"));
    // Curve25519 signs deterministically, where OpenPGP's P-256 signatures are randomized
    assert_eq!(
        with_table(&["--algorithm", "curve25519"], "pgp"),
        publish(&[], "pgp"),
        "the table beat a flag"
    );
}

/// `set --save` writes what it sets to the user's config file, where the next run reads it:
/// created owner-only with a header, edited in place with its comments kept, and checked by
/// the same table as `set`, so a secret or a typo leaves it as it was. `unset --save` takes a
/// default out again, and both work in a session too.
#[test]
fn saved_defaults_outlast_the_run() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("mind-the-gap").join("config.toml");
    let run = |args: &[&str]| {
        let mut cmd = bin();
        cmd.env("XDG_CONFIG_HOME", dir.path());
        cmd.args(args).output().unwrap()
    };

    let out = run(&["set", "--save", "name=Jane Doe", "emails=jane@example.org"]);
    assert!(out.status.success(), "set --save failed:\n{}", stderr(&out));
    let text = std::fs::read_to_string(&config).unwrap();
    assert!(text.starts_with("# mind-the-gap defaults"), "no header:\n{text}");
    assert!(text.contains("name = \"Jane Doe\""), "{text}");
    assert!(text.contains("emails = [\"jane@example.org\"]"), "{text}");
    #[cfg(unix)]
    assert_eq!(crate::mode(&config), 0o600, "a new config file is not owner-only");

    // The next run reads it
    let mut cmd = bin();
    cmd.env("XDG_CONFIG_HOME", dir.path());
    assert_eq!(root_subject(&root_pem(cmd, &[])), "CN=Jane Doe PIV Root CA p256");

    // Edited in place, the rest of the file as it was
    std::fs::write(
        &config,
        "# mine\nname = \"Jane Doe\" # who\n\n[pgp]\nalgorithm = \"rsa2048\"\n",
    )
    .unwrap();
    let out = run(&["set", "--save", "name=Jane", "pgp.lang=de"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        "# mine\nname = \"Jane\" # who\n\n[pgp]\nalgorithm = \"rsa2048\"\nlang = [\"de\"]\n"
    );

    // Refused as `set` refuses, and the file left alone
    let before = std::fs::read_to_string(&config).unwrap();
    for setting in [
        "seed=abandon",
        "pin=123456",
        "yes=true",
        "policy=strickt",
        "colour=red",
    ] {
        let out = run(&["set", "--save", "name=Other", setting]);
        assert!(!out.status.success(), "set --save {setting} ran");
        assert_eq!(std::fs::read_to_string(&config).unwrap(), before, "{setting} wrote");
    }
    assert!(!stderr(&run(&["set", "--save", "seed=abandon"])).contains("abandon "));

    let out = run(&["unset", "--save", "pgp.algorithm", "lang"]);
    assert!(!out.status.success(), "unset --save forgot what the file does not hold");
    assert_eq!(std::fs::read_to_string(&config).unwrap(), before, "a failed unset wrote");
    let out = run(&["unset", "--save", "pgp.algorithm", "pgp.lang"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        "# mine\nname = \"Jane\" # who\n\n[pgp]\n"
    );

    // In a session, the default holds for the session and is written for the next
    let mut cmd = bin();
    cmd.env("XDG_CONFIG_HOME", dir.path());
    let out = repl_with(cmd, "set --save subkey=laptop\nset\nunset --save name\nset\n", &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(listed(&text, "set", "subkey = laptop"), "{text}");
    let after = text.rsplit("Config files:").next().unwrap();
    assert!(listed(&text, "user", "name = Jane"), "the file's name was not read:\n{text}");
    assert!(!after.contains("name = Jane"), "unset --save left the name:\n{text}");
    assert_eq!(std::fs::read_to_string(&config).unwrap(), "# mine\nsubkey = \"laptop\"\n\n[pgp]\n");
}

/// `--save` changes the defaults it was asked to and no other, wherever the reader finds them:
/// a table written `[ pgp ]` is the `[pgp]` table to both. `unset --save` of what the file
/// does not hold leaves it unwritten, a `--config` file not yet there is created as the user's
/// would be, a file its owner may not write is left alone, and a control character goes in
/// escaped and comes back as it was.
#[test]
fn saving_edits_only_what_was_asked() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let run = |args: &[&str]| {
        bin()
            .arg("--config")
            .arg(&config)
            .args(args)
            .output()
            .unwrap()
    };
    let listing = || stdout(&run(&["set"]));

    std::fs::write(&config, "[ pgp ]\nalgorithm = \"rsa2048\"\n").unwrap();
    let out = run(&["set", "--save", "subkey=laptop", "algorithm=p256"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = listing();
    assert!(listed(&text, "user", "subkey = laptop"), "{text}");
    assert!(listed(&text, "user", "algorithm = p256"), "{text}");
    assert!(listed(&text, "user", "pgp.algorithm = rsa2048"), "{text}");
    let out = run(&["unset", "--save", "algorithm"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = listing();
    assert!(listed(&text, "user", "pgp.algorithm = rsa2048"), "the table's line went:\n{text}");
    assert!(!text.contains("  algorithm = p256"), "{text}");

    // Nothing in the file to forget, and the session's `set` the only holder: no write
    let fresh = dir.path().join("fresh.toml");
    let out = repl_with(
        {
            let mut cmd = bin();
            cmd.arg("--config").arg(&fresh);
            cmd
        },
        "set --save subkey=a\nset subkey=b\nunset --save subkey\n",
        &[],
    );
    assert!(!out.status.success(), "the session ran without its --config file");
    let missing = dir.path().join("missing.toml");
    let out = bin()
        .arg("--config")
        .arg(&missing)
        .args(["publish"])
        .output()
        .unwrap();
    assert!(stderr(&out).contains("`set --save` creates it"), "{}", stderr(&out));
    assert!(!missing.exists(), "a run that only reads created the file");

    // `set --save` creates the --config file, owner-only, with its header
    let out = bin()
        .arg("--config")
        .arg(&fresh)
        .args(["set", "--save", "name=Jane\u{1}Doe"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let text = std::fs::read_to_string(&fresh).unwrap();
    assert!(text.starts_with("# mind-the-gap defaults"), "{text}");
    assert!(text.contains("name = \"Jane\\u0001Doe\""), "{text}");
    assert!(!text.contains('\u{1}'), "a raw control character went into the file");
    #[cfg(unix)]
    assert_eq!(crate::mode(&fresh), 0o600);
    let shown = stdout(
        &bin()
            .arg("--config")
            .arg(&fresh)
            .arg("set")
            .output()
            .unwrap(),
    );
    assert!(shown.contains("name = Jane\\u{1}Doe"), "{shown}");

    // A session holding the default alone forgets it without touching the file
    let before = std::fs::read_to_string(&fresh).unwrap();
    let out = repl_with(
        {
            let mut cmd = bin();
            cmd.arg("--config").arg(&fresh);
            cmd
        },
        "set subkey=b\nunset --save subkey\n",
        &[],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(std::fs::read_to_string(&fresh).unwrap(), before);

    // Nor does a one-shot `unset --save` of what no file holds create one
    let none = dir.path().join("xdg");
    let out = bin()
        .env("XDG_CONFIG_HOME", &none)
        .args(["unset", "--save", "subkey"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "unset --save forgot what nothing held");
    assert!(!none.exists(), "unset --save created a file:\n{}", stderr(&out));

    // A file its owner may not write is left alone
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fresh, std::fs::Permissions::from_mode(0o400)).unwrap();
        let out = bin()
            .arg("--config")
            .arg(&fresh)
            .args(["set", "--save", "subkey=x"])
            .output()
            .unwrap();
        assert!(!out.status.success(), "a read-only config was replaced");
        assert!(stderr(&out).contains("read-only to its owner"), "{}", stderr(&out));
        assert_eq!(std::fs::read_to_string(&fresh).unwrap(), before);
    }
}

/// A file `--save` cannot own is refused: a link to a file kept elsewhere, as a managed home
/// links its config
#[test]
#[cfg(unix)]
fn saving_refuses_a_linked_config() {
    let dir = tempfile::tempdir().unwrap();
    let kept = dir.path().join("kept.toml");
    std::fs::write(&kept, "name = \"Kept\"\n").unwrap();
    let link = dir.path().join("config.toml");
    std::os::unix::fs::symlink(&kept, &link).unwrap();
    let out = bin()
        .args([
            "--config",
            link.to_str().unwrap(),
            "set",
            "--save",
            "name=Other",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "--save wrote through a link");
    assert!(stderr(&out).contains("is a link"), "{}", stderr(&out));
    assert_eq!(std::fs::read_to_string(&kept).unwrap(), "name = \"Kept\"\n");
}

/// `set --help` lists every name a default takes, grouped as the options are in a verb's
/// help, and no secret or option of one command among them; a name that is none says which
/// it is closest to, or where they are listed.
#[test]
fn set_names_its_settings() {
    let text = stdout(&bin().args(["set", "--help"]).output().unwrap());
    let names = text
        .split("The names a default takes")
        .nth(1)
        .unwrap_or_else(|| panic!("no names in:\n{text}"));
    let group = |heading: &str| {
        names
            .lines()
            .find(|line| line.trim_start().starts_with(heading))
            .unwrap_or_else(|| panic!("no {heading} in:\n{names}"))
            .to_string()
    };
    assert!(group("Card:").contains("policy"), "{names}");
    assert!(group("Derivation:").contains("subkey"), "{names}");
    assert!(group("Keys:").contains("slot"), "{names}");
    assert!(group("`run`:").contains("ceremony"), "{names}");
    assert!(names.contains("validity"), "{names}");
    for word in [
        "seed",
        "password",
        " pin",
        "current-pin",
        "yes",
        "dry-run",
        " to,",
        "save",
    ] {
        assert!(!names.contains(word), "{word} is offered as a default:\n{names}");
    }

    let out = repl("set plicy=strict\nset pgp.algoritmh=rsa2048\nset colour=red\n", &[]);
    let err = stderr(&out);
    assert!(err.contains("the closest is `policy`"), "{err}");
    assert!(err.contains("the closest is `pgp.algorithm`"), "{err}");
    assert!(err.contains("`colour` is no option; `set --help` lists"), "{err}");

    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "[pgp]\nalgoritmh = \"rsa2048\"\n").unwrap();
    let out = bin()
        .args(["--config", config.to_str().unwrap(), "set"])
        .output()
        .unwrap();
    assert!(stderr(&out).contains("the closest is `pgp.algorithm`"), "{}", stderr(&out));
}
