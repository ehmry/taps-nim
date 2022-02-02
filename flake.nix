{
  description = "TAPS for Nim";

  outputs = { self, nixpkgs }:
    let inherit (nixpkgs) lib;
    in {

      devShell = lib.attrsets.mapAttrs (system: pkgs:
        with pkgs;
        pkgs.mkShell { packages = [ nimPackages.c2nim pkg-config solo5 tup ]; }) {
          inherit (nixpkgs.legacyPackages) x86_64-linux;
        };

    };
}
