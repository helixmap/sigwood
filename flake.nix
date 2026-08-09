{
  description = "sigwood development environment";

  inputs = {
    nixpkgs.url = "flake:nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        # Manylinux wheels (numpy/pandas/scikit-learn/awscrt/...) link against
        # libstdc++ and friends at their standard FHS paths, which don't exist
        # on NixOS. Without this on LD_LIBRARY_PATH, `import numpy` fails with
        # "libstdc++.so.6: cannot open shared object file".
        wheelLibs = pkgs.lib.makeLibraryPath [
          pkgs.stdenv.cc.cc.lib
          pkgs.zlib
        ];

        # Native stack for the optional `pdf` extra (WeasyPrint). Not installed
        # by default - `.[dev]` below deliberately excludes `pdf` per
        # CONTRIBUTING.md. This just puts Pango/HarfBuzz/fontconfig/cairo on
        # LD_LIBRARY_PATH so `pip install -e '.[dev,pdf]'` works for
        # contributors who opt into PDF output, without them hunting down
        # the native libs pip can't supply on its own.
        weasyprintLibs = pkgs.lib.makeLibraryPath [
          pkgs.pango
          pkgs.harfbuzz
          pkgs.fontconfig
          pkgs.cairo
          pkgs.gdk-pixbuf
          pkgs.glib
        ];
      in
      {
        devShells.default = pkgs.mkShell {
          # sigwood's CI matrix covers 3.11-3.14 and deliberately doesn't pin
          # one version for local dev - pkgs.python3 tracks nixpkgs' current
          # default rather than freezing this shell to 3.11.
          packages = [ pkgs.python3 pkgs.git ];

          LD_LIBRARY_PATH = "${wheelLibs}:${weasyprintLibs}";

          shellHook = ''
            venvPython="${pkgs.python3}/bin/python3"
            shellVersion="$("$venvPython" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"

            # .venv is also the convention documented in CONTRIBUTING.md for
            # manual (non-Nix) setup, so we reuse it rather than diverging to
            # .direnv - but if it was built against a different interpreter
            # than this shell provides, its compiled wheels are incompatible,
            # so recreate it instead of silently activating a stale venv.
            if [ -d .venv ]; then
              venvVersion="$(.venv/bin/python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo "")"
              if [ "$venvVersion" != "$shellVersion" ]; then
                echo "sigwood: .venv is python $venvVersion, this shell provides $shellVersion - recreating"
                rm -rf .venv
              fi
            fi

            if [ ! -d .venv ]; then
              echo "sigwood: creating .venv"
              "$venvPython" -m venv .venv
            fi
            source .venv/bin/activate

            # Cheap idempotency check: only reinstall when pyproject.toml
            # changed since the last install.
            sigwood_install_ok=1
            if [ ! -f .venv/.sigwood-dev-installed ] || [ pyproject.toml -nt .venv/.sigwood-dev-installed ]; then
              echo "sigwood: syncing .venv with pip install -e '.[dev]'"
              if python -m pip install -e '.[dev]'; then
                touch .venv/.sigwood-dev-installed
              else
                sigwood_install_ok=0
              fi
            fi

            if [ "$sigwood_install_ok" = "1" ]; then
              echo "sigwood devenv ready - python $(python3 --version 2>&1 | cut -d' ' -f2), venv at .venv"
              echo "run tests with: python -m pytest"
            else
              echo "sigwood: pip install -e '.[dev]' failed - devenv is NOT ready" >&2
              exit 1
            fi
          '';
        };
      });
}
