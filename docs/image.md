# Building an image

The live image is a NixOS system, and `nix build github:gliology/mind-the-gap#iso` builds the
stock one: the tool, an interactive session, and every way out of the machine taken away;
[the live image](live-image.md) says how it is used. An image of your own adds your defaults
and a [ceremony](ceremonies.md), read-only, so that a stick built for a team carries the
team's settings and its procedure, and nobody at the keyboard changes either by accident.

## The NixOS module

The flake exports the tool as a NixOS module, `nixosModules.default`, which installs the
package and writes what an image ships with into `/etc/mind-the-gap/`. A machine of your own
imports it from its flake:

```nix
# flake.nix
{
  inputs.mind-the-gap.url = "github:gliology/mind-the-gap";

  outputs = { nixpkgs, mind-the-gap, ... }: {
    nixosConfigurations.workstation = nixpkgs.lib.nixosSystem {
      modules = [
        ./configuration.nix
        { imports = [ mind-the-gap.nixosModules.default ]; }
      ];
    };
  };
}
```

and sets what the machine ships with:

```nix
programs.mind-the-gap = {
  enable = true;

  # /etc/mind-the-gap/config.toml: the defaults every command starts from
  config = {
    name = "Jane Doe";
    emails = [ "jane@example.com" ];
    policy = "strict";
    pgp.algorithm = "rsa2048";
  };

  # /etc/mind-the-gap/ceremony: recipes of commands, the first one run by a bare mind-the-gap
  ceremony = ''
    card: init keys

    init:
        init --yes

    keys:
        upload --yes
        publish --to certs/
  '';
};
```

- **`config`** names the defaults by the options' long names, as a [config
  file](configuration.md#config-files) does; `piv` and `pgp` hold defaults for that applet
  alone. A user's own config file and `set` in a session override them, a command's flags
  override all.
- **`ceremony`** is a [ceremony file](ceremonies.md#the-file). With one, a bare `mind-the-gap`
  runs its first recipe, then opens the session, and `mind-the-gap run <recipe>` runs any
  other.

Neither may hold a secret: the tool refuses seeds, passwords and pins as defaults, and a
ceremony asks for them or takes them from the environment. Both files are checked when the
system is built, by the tool itself, wherever the build machine can run it: the config is read
the way every command reads it, and the ceremony goes through
[`run --check`](ceremonies.md#trying-one-first). A misspelt name, a value an option does not take, a
secret, a nested `run` or a cycle between recipes fails the build rather than every command on
the machine. Both end up in the store, which nothing on the machine can change.

The module also sets **`defaultRecipe`**, read-only: the recipe a bare `mind-the-gap` runs,
the ceremony's first, for a login banner to name.

The module works on any NixOS machine, but it is only the tool and its files: none of the
image's lockdowns come with it.

## An image of your own

The stock image is the flake's `nixosConfigurations.live-<system>`; extend it with a module
of your own and build its iso:

```nix
# flake.nix
{
  inputs.mind-the-gap.url = "github:gliology/mind-the-gap";

  outputs = { mind-the-gap, ... }: {
    packages.x86_64-linux.iso =
      (mind-the-gap.nixosConfigurations.live-x86_64-linux.extendModules {
        modules = [ ./image.nix ];
      }).config.system.build.isoImage;
  };
}
```

with `image.nix` setting `programs.mind-the-gap.config` and `.ceremony` as above (the image
enables the module already). `nix build .#iso` then builds the image, the `.iso` file in
`result/iso/` (`mind_the_gap-<version>-<label>-x86_64-linux.iso`), to be written to a stick
like the stock one. The `image-ceremony` check in the repository (`nix/tests/`) is the
executable specification of such an image: it configures both through the module, runs the
ceremony against a virtual card, and checks the dry run, the recording and plumbing mode.

## What the image locks down

An image built this way keeps every measure of the stock one: no network and no radios,
kernel modules locked after boot, RAM zeroed on free and never swapped or suspended, no kexec
and no pstore, the tool locked into memory, and no shell history file. The [security
chapter](security.md#the-live-image) says what each measure is for, and what it cannot do.
