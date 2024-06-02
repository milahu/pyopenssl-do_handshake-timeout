{ pkgs ? import <nixpkgs> { }
  #pkgs ? import ./. {}
}:

pkgs.mkShell {
  buildInputs = with pkgs; [
    gnumake
    (python3.withPackages (pp: with pp; [
      pyopenssl
      cryptography
      certifi
      timeout-decorator

      # test
      pycurl

      # dev
      black
    ]))
  ];
}
