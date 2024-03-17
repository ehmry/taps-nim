let pkgs = import <nixpkgs> { };
in pkgs.buildNimPackage {
  name = "dummy";
  buildInputs = [ pkgs.getdns ];
  nativeBuildInputs = [ pkgs.pkg-config ];
}
