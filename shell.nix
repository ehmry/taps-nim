let pkgs = import <nixpkgs> { };
in pkgs.buildNimPackage {
  name = "dummy";
  buildInputs = builtins.attrValues { inherit (pkgs) getdns solo5; };
  nativeBuildInputs = builtins.attrValues { inherit (pkgs) pkg-config solo5; };
}
