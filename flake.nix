{
  description = "SCSI Tape Encryption Manager";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, nixpkgs }: {
    packages = nixpkgs.lib.genAttrs ["x86_64-linux"] (system:
    let
      pkgs = import nixpkgs { inherit system; };
    in
    {
      stenc = pkgs.stdenv.mkDerivation {
        pname = "stenc";
        version = "2.0.1";
        src = ./.;
        
        nativeBuildInputs = with pkgs; [
          autoreconfHook 
          pandoc 
          pkg-config 
        ];

        meta = with pkgs.lib; {
          description = "SCSI Tape Encryption Manager";
          license = licenses.gpl2;
          maintainers = with maintainers; [ llamato ];
          platforms = platforms.unix;
        };
      };

      devShells.${system}.default = pkgs.mkShell {
        nativeBuildInputs = with pkgs; [ 
          autoconf
          automake
          libtool
          pkg-config
          pandoc
        ];

        buildInputs = with pkgs; [
          bash-completion
          clang
          gcc
          gdb
        ];

        shellHook = ''
          autoreconf -fi
          ./configure
          make
        '';
      };
    });

    defaultPackage = {
      x86_64-linux = self.packages.x86_64-linux.stenc;
    };
  };
}