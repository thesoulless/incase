{
  description = "";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    devenv.url = "github:cachix/devenv";
    mk-shell-bin.url = "github:rrbutani/nix-mk-shell-bin";
  };

  nixConfig = {
    extra-trusted-public-keys =
      "devenv.cachix.org-1:w1cLUi8dv3hnoSPGAuibQv+f9TZLr6cv/Hm9XgU50cw=";
    extra-substituters = "https://devenv.cachix.org";
  };

  outputs = inputs@{ flake-parts, nixpkgs, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [ inputs.devenv.flakeModule ];
      systems = [
        "x86_64-linux"
        "x86_64-darwin"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      perSystem = { config, self', inputs', pkgs, system, ... }: {
        # Per-system attributes can be defined here. The self' and inputs'
        # module parameters provide easy access to attributes of the same
        # system.
        devenv.shells.default = {
          name = "";

          imports = [
            # This is just like the imports in devenv.nix.
            # See https://devenv.sh/guides/using-with-flake-parts/#import-a-devenv-module
            # ./devenv-foo.nix
          ];

          # https://devenv.sh/reference/options/
          packages = with pkgs; [
            # gotools
            # go-tools
            # govulncheck
            # gopls
            nodejs_22
          ];

          # https://devenv.sh/basics/
          env = { GREET = "Your dev env is all set 🍻"; };

          # https://devenv.sh/scripts/
          scripts.hello.exec = "echo $GREET";

          enterShell = ''
            hello
          '';

          # https://devenv.sh/languages/
          languages.go = {
              enable = true;
          };

          # Make diffs fantastic
          difftastic.enable = true;

          # https://devenv.sh/pre-commit-hooks/
          pre-commit.hooks = { };

          # Plugin configuration
          pre-commit.settings = { };

          services = {
            # https://devenv.sh/services/
            postgres = {
              enable = true;
              package = pkgs.postgresql_15;
              listen_addresses = "127.0.0.1";
              initialDatabases = [{
                  name = "incase";
                  user = "incase";
                  pass = "incase";
                  # port = 5435;
              }];
              initialScript =
                ''
                  CREATE USER incase WITH PASSWORD 'incase';
                  CREATE DATABASE incase OWNER incase;
                ''
              ;
              port = 5435;
            };
          };
        };
      };

      flake = {};
    };
}
