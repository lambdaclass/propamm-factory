{
  description = "propamm-factory: the tools every make target needs";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
    # The exact Rust from rust-toolchain.toml, which nixpkgs alone does not carry.
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
        rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            # The contracts and the local chain: forge, anvil, cast.
            pkgs.foundry
            # The quote updater, pinned to the version CI builds with.
            rust
            # e2e/: the mocks of the chain, the builders and the exchange.
            (pkgs.python3.withPackages (ps: [ ps.aiohttp ps.websockets ]))
            # `make quickstart` runs both natively, with the production dashboard and rules.
            pkgs.prometheus
            pkgs.grafana
            pkgs.git
            pkgs.gnumake
            pkgs.curl
            pkgs.jq
            # The TLS the exchange and builder websockets use links against the system OpenSSL.
            pkgs.pkg-config
            pkgs.openssl
          ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [ pkgs.libiconv ];
        };
      });
}
