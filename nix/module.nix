# The NixOS module for mind-the-gap: the package, and the defaults and ceremony a machine
# ships with, read-only in the store
#
# `config` becomes /etc/mind-the-gap/config.toml, the defaults every command starts from,
# named like the options (`name`, `emails`, `policy`, ...). `ceremony` becomes
# /etc/mind-the-gap/ceremony, and with it a bare `mind-the-gap` runs the ceremony's first
# recipe before it starts the session. Neither may hold a secret: the tool refuses seeds,
# passwords and pins as defaults, and a ceremony asks for them or takes them from the
# environment.
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.programs.mind-the-gap;

  # One `name = value` line per default, each value in TOML's own JSON-shaped spelling: a
  # quoted string, a boolean, an integer or an array of strings on one line, and an applet's
  # own defaults as dotted keys, `piv.algorithm = ...`. Rendered here rather than through
  # pkgs.formats.toml, whose arrays may span lines, which the tool's reader does not take.
  line = name: value: "${name} = ${builtins.toJSON value}\n";
  rendered = pkgs.writeText "mind-the-gap-config.toml" (
    lib.concatStrings (
      lib.mapAttrsToList (
        name: value:
        if builtins.isAttrs value then
          lib.concatStrings (lib.mapAttrsToList (option: line "${name}.${option}") value)
        else
          line name value
      ) cfg.config
    )
  );

  # The tool reads the file before any command, so one it refuses (a misspelt name, a value
  # its option does not take, an escape its reader has not) would leave every command on the
  # machine failing; read here, it fails the build instead. The ceremony likewise: `run
  # --check` refuses a file with a secret, a nested run or a cycle in any recipe, and touches
  # no card doing so.
  checkable = pkgs.stdenv.buildPlatform.canExecute pkgs.stdenv.hostPlatform;
  tool = lib.getExe' cfg.package "mind-the-gap";
  configFile =
    if checkable then
      pkgs.runCommand "mind-the-gap-config.toml" { } ''
        XDG_CONFIG_HOME=$TMPDIR ${tool} --config ${rendered} --help > /dev/null
        cp ${rendered} $out
      ''
    else
      rendered;
  ceremonyText = pkgs.writeText "mind-the-gap-ceremony" cfg.ceremony;
  ceremonyFile =
    if checkable then
      pkgs.runCommand "mind-the-gap-ceremony" { } ''
        XDG_CONFIG_HOME=$TMPDIR ${tool} ${
          lib.optionalString (cfg.config != { }) "--config ${configFile}"
        } run --check --ceremony ${ceremonyText} > /dev/null
        cp ${ceremonyText} $out
      ''
    else
      ceremonyText;

  # The ceremony's recipe headers as the tool reads them: every line that is neither a step
  # (indented), nor a comment, nor empty
  headers = builtins.filter (line: line != "" && builtins.match "[[:space:]#].*" line == null) (
    lib.splitString "\n" cfg.ceremony
  );
  recipeName = header: builtins.match "([a-z0-9-]+)[[:space:]]*:.*" header;
  # The recipe a bare `mind-the-gap` runs: the first one, as the tool picks it
  firstRecipe =
    if headers == [ ] then null else lib.head (lib.toList (recipeName (builtins.head headers)));
in
{
  options.programs.mind-the-gap = {
    enable = lib.mkEnableOption "mind-the-gap, which derives smart card keys from seed phrases";

    package = lib.mkPackageOption pkgs "mind-the-gap" { };

    config = lib.mkOption {
      type =
        with lib.types;
        let
          value = oneOf [
            str
            bool
            int
            (listOf str)
          ];
        in
        attrsOf (either value (attrsOf value));
      default = { };
      example = {
        name = "Jane Doe";
        emails = [ "jane@example.com" ];
        policy = "strict";
        pgp.algorithm = "rsa2048";
      };
      description = ''
        Defaults every command starts from, by the options' long names, written to
        /etc/mind-the-gap/config.toml; `piv` and `pgp` hold defaults for that applet alone.
        A user's own config file and `set` in a session override them, a command's flags
        override all. Secrets are no defaults.
      '';
    };

    ceremony = lib.mkOption {
      type = lib.types.nullOr lib.types.lines;
      default = null;
      example = ''
        card: init keys

        init:
            init --yes

        keys:
            upload --yes
            publish --to certs/
      '';
      description = ''
        A ceremony file, written to /etc/mind-the-gap/ceremony: recipes of commands with the
        recipes they depend on. With one, a bare `mind-the-gap` runs its first recipe, then
        opens the session, and `mind-the-gap run <recipe>` runs any other.
      '';
    };

    defaultRecipe = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      readOnly = true;
      default = if cfg.ceremony == null then null else firstRecipe;
      description = "The recipe a bare `mind-the-gap` runs, the ceremony's first, for login banners.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.ceremony == null || firstRecipe != null;
        message = "programs.mind-the-gap.ceremony has no recipe";
      }
      {
        assertion = cfg.ceremony == null || lib.all (header: recipeName header != null) headers;
        message = "programs.mind-the-gap.ceremony: a recipe is `name: dependencies`, named in lowercase letters, digits and hyphens, and its steps are indented";
      }
      {
        assertion = lib.all (
          name:
          builtins.elem name [
            "piv"
            "pgp"
          ]
        ) (lib.attrNames (lib.filterAttrs (_: builtins.isAttrs) cfg.config));
        message = "programs.mind-the-gap.config takes tables for `piv` and `pgp` alone";
      }
    ];

    environment.systemPackages = [ cfg.package ];

    environment.etc."mind-the-gap/config.toml" = lib.mkIf (cfg.config != { }) {
      source = configFile;
    };
    environment.etc."mind-the-gap/ceremony" = lib.mkIf (cfg.ceremony != null) {
      source = ceremonyFile;
    };
  };
}
