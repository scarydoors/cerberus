let
  pkgs = import <nixpkgs> {};
in
  with pkgs;
mkShell {
  buildInputs = [
    rustup
    pkg-config
    gtk3
    webkitgtk_4_1
    bun
  ];
}
