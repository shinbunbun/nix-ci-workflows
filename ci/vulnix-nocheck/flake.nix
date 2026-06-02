{
  # vulnix の checkPhase (pytest src/vulnix) を無効化した版を提供する wrapper flake。
  # 用途: vulnxscan を aarch64-darwin で動かすため。vulnix の checkPhase が
  # socket/network test を含み、darwin の nix build sandbox では loopback bind が
  # 不許可 (PermissionError) / DNS 不可 (gaierror) で失敗しビルドできないため。
  #
  # scan-vulnerabilities.yaml が darwin scan 時に以下で利用する:
  #   nix run github:tiiuae/sbomnix#vulnxscan \
  #     --override-input vulnix path:<checkout>/ci/vulnix-nocheck -- <target> --triage
  description = "vulnix with checkPhase disabled (darwin sandbox compatibility)";

  inputs.vulnix.url = "github:nix-community/vulnix";

  outputs =
    { vulnix, ... }:
    {
      # 注意: vulnix は checkPhase = "pytest src/vulnix" を明示上書きしており、
      # buildPythonPackage は user の checkPhase を installCheckPhase (doInstallCheck 管理)
      # に移送するため、doCheck=false だけでは pytest が止まらない。checkPhase と
      # installCheckPhase の両方を no-op にする必要がある。
      packages = builtins.mapAttrs (
        _system: ps:
        let
          noCheck = ps.vulnix.overrideAttrs (_: {
            doCheck = false;
            checkPhase = "true";
            installCheckPhase = "true";
          });
        in
        {
          vulnix = noCheck;
          default = noCheck;
        }
      ) vulnix.packages;
    };
}
