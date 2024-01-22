
with import <nixpkgs> {};
let
  my-python = pkgs.python3;
  python-with-my-packages = my-python.withPackages (p: with p; [
  ]);
in
{ pkgs ? import <nixpkgs> {} }:

stdenv.mkDerivation {
  name = "python-opensnitch";
  src = ./.;

   buildInputs = with pkgs; [
     python-with-my-packages
     git
   ];
   shellHook = ''
      PYTHONPATH=${python-with-my-packages}/${python-with-my-packages.sitePackages}
   ''; 
}
