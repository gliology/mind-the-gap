# The documentation: the book rendered from docs/, the site the pages workflow
# publishes, and the checks that guard the book's sources
{ pkgs, rustdoc }:

let
  # Render the documentation site from docs/, which is the book source
  book = pkgs.stdenvNoCC.mkDerivation {
    name = "mind-the-gap-book";

    # Only the book's own inputs, so a change to rust sources or the nix files
    # leaves this derivation -- and the site the pages workflow pulls from the
    # binary cache -- untouched
    src = pkgs.lib.fileset.toSource {
      root = ../.;
      # theme/ carries only the favicon overrides; without it here the book
      # would silently build with mdBook's stock icons
      fileset = pkgs.lib.fileset.unions [
        ../book.toml
        ../docs
        ../theme
      ];
    };

    nativeBuildInputs = [ pkgs.mdbook ];

    buildPhase = "mdbook build --dest-dir $TMPDIR/book";
    installPhase = "cp -r $TMPDIR/book $out";
  };

  # Bundle what the pages workflow publishes: the book at the root of the site,
  # the developer reference under /rustdoc
  site = pkgs.runCommand "mind-the-gap-site" { } ''
    cp -r ${book} $out
    chmod -R +w $out
    cp -r ${rustdoc}/share/doc $out/rustdoc
  '';
in
{
  inherit book site;

  checks = {
    # Rendering the book is its own check: mdbook fails on a malformed SUMMARY.md
    # or a broken template, and the rendered site lands in the cache for the pages
    # workflow to pull
    inherit book;

    # Rustdoc has its own failure modes -- a broken intra-doc link, a public item
    # the missing_docs lint catches -- that neither clippy nor the book check sees
    inherit rustdoc;

    # What mdbook will not tell us: whether docs/ and docs/SUMMARY.md describe the
    # same set of chapters. It is silent in both directions -- a file the summary
    # omits is never rendered and drops out of the sidebar, and an entry with no
    # file behind it makes mdbook create an empty stub and publish that -- so
    # compare the two sets outright.
    docs-summary = pkgs.runCommand "check-docs-summary" { docs = ../docs; } ''
      if diff -u \
        --label 'listed in docs/SUMMARY.md' <(
          grep -o '](\([^)]*\.md\))' $docs/SUMMARY.md \
            | sed 's|^](||; s|)$||; s|^\./||' | sort -u
        ) \
        --label 'present in docs/' <(
          cd $docs && find . -name '*.md' -printf '%P\n' \
            | grep -vx 'SUMMARY.md' | sort
        )
      then
        touch $out
      else
        echo "error: docs/SUMMARY.md and docs/ describe different chapters" >&2
        echo "  a '-' line is a summary entry with no file behind it" >&2
        echo "  a '+' line is a chapter the summary leaves out" >&2
        exit 1
      fi
    '';

    # Relative links need no network to verify, which is the half of link checking
    # that a sandbox can do honestly: a link to a chapter that is not there renders
    # as a 404 and mdbook reports nothing. Web links are left to rot on purpose --
    # there is no network here, and an unreachable third party site is no reason to
    # fail a build. Inline `](target)` links only, which is every link the book
    # uses; a fragment is stripped before the lookup, so this proves the file is
    # there and says nothing about the anchor inside it.
    docs-links = pkgs.runCommand "check-docs-links" { docs = ../docs; } ''
      cd $docs

      fail=0
      while IFS=$'\t' read -r page target; do
        case $target in
          # Same-page anchor, web link, or mail address
          "" | '#'* | *://* | mailto:*) continue ;;
        esac

        # Resolve against the page doing the linking, the way a reader's browser
        # would; -m normalises `..` without needing the path to exist yet
        rel=$(realpath -m --relative-to=. "$(dirname "$page")/''${target%%#*}")

        case $rel in
          ../*)
            echo "error: $page links to $target, which is outside docs/" >&2
            echo "  the site only carries docs/, so that link 404s once rendered" >&2
            fail=1
            continue
            ;;
        esac

        if [ ! -e "$rel" ]; then
          echo "error: $page links to $target, which does not exist" >&2
          fail=1
        fi
      done < <(
        find . -name '*.md' -print0 \
          | xargs -0 grep -o '](\([^)]*\))' /dev/null \
          | sed 's|:](|\t|; s|)$||'
      )

      [ $fail -eq 0 ] || exit 1
      touch $out
    '';
  };
}
