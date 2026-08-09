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

        # Native stack for the optional `pdf` extra (WeasyPrint). See
        # CONTRIBUTING.md: pip can't supply Pango/HarfBuzz/fontconfig/cairo.
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
          packages = [ pkgs.python311 pkgs.git ];

          LD_LIBRARY_PATH = "${wheelLibs}:${weasyprintLibs}";

          shellHook = ''
            if [ ! -d .venv ]; then
              echo "sigwood: creating .venv"
              python3 -m venv .venv
            fi
            source .venv/bin/activate

            # Cheap idempotency check: only reinstall when pyproject.toml
            # changed since the last install.
            if [ ! -f .venv/.sigwood-dev-installed ] || [ pyproject.toml -nt .venv/.sigwood-dev-installed ]; then
              echo "sigwood: syncing .venv with pip install -e '.[dev]'"
              pip install -q -e '.[dev]' && touch .venv/.sigwood-dev-installed
            fi

            echo "sigwood devenv ready - python $(python3 --version 2>&1 | cut -d' ' -f2), venv at .venv"
            echo "run tests with: python -m pytest"
          '';
        };
      });
}
