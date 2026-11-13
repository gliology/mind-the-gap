# The console a session runs on: kmscon on the virtual consoles, the banner before every
# login, no shell history on disk, and `forget` to clear what a session left on the
# terminal.
{
  config,
  lib,
  pkgs,
  ...
}:

{
  options.mind-the-gap.banner = lib.mkOption {
    type = lib.types.lines;
    description = ''
      The pre-login reminder, in /etc/issue: the serial gettys show it before login, and
      kmscon shows it above its session. The VT and kmscon both speak truecolor escapes.
    '';
  };

  config = {
    # Adds terminus_font for people with HiDPI displays
    console.packages = lib.mkOptionDefault [ pkgs.terminus_font ];

    # Clear the traces a session leaves on the terminal: scrollback, screen and, via the
    # shell alias below, the shell history. For leaving a machine mid-session; powering off
    # does strictly more.
    environment.systemPackages = [
      (pkgs.writeShellScriptBin "forget" ''
        # RIS (ESC c) is what clears kmscon's scrollback: its libtsm takes no 3J. 2J clears
        # the screen, 3J the scrollback of terminals that honour it, H homes the cursor;
        # reset restores whatever state a crashed ceremony might have left
        printf '\033c\033[2J\033[3J\033[H'
        tput reset 2>/dev/null || true
      '')
    ];

    programs.bash = {
      # `forget` must run in the interactive shell itself: a child process cannot clear its
      # parent's in-memory history, so the alias chains `history -c` in front of the script
      # that wipes the terminal.
      shellAliases.forget = "history -c; command forget";
      # No shell writes its history to a file, so every line typed ends with the shell that
      # holds it: `forget` clears the running one, and an exited shell leaves nothing behind
      interactiveShellInit = "unset HISTFILE";
    };

    # A userspace terminal on the virtual consoles instead of the kernel VT: tty1 gains a
    # real alternate screen, so the QR viewer vanishes without a trace on dismissal, plus
    # clean rendering of the half-block QR glyphs and live font zoom with
    # Ctrl+Alt+Plus/Minus when a dense code needs more rows than the screen has.
    services.kmscon = {
      enable = true;
      fonts = [
        {
          name = "DejaVu Sans Mono";
          package = pkgs.dejavu_fonts;
        }
      ];
      # Small enough that a certificate-sized QR fits on one 1080p screen
      extraConfig = "font-size=12";
    };

    # The banner, in /etc/issue: the gettys (serial console) show it before login, and
    # kmscon (9.x) shows it as well, so no shell prints it again
    services.getty.helpLine = config.mind-the-gap.banner;
  };
}
