{
  description = "Nix CI/CD 共有ツール - Attic CLI, deploy-rs をプリビルドで提供";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

    attic = {
      url = "github:zhaofengli/attic";
    };

    deploy-rs = {
      url = "github:serokell/deploy-rs";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      attic,
      deploy-rs,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
    in
    {
      packages = forAllSystems (system: {
        attic = attic.packages.${system}.default;
        deploy-rs = deploy-rs.packages.${system}.deploy-rs;
      });

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixfmt-tree);
    };
}
