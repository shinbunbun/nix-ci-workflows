# vulnxscan 由来解決用: 宣言ルート (declared roots) を列挙する。
#
# 「脆弱パッケージが closure に入った設定上の入口」を特定するため、NixOS/Darwin の
# module system が保持する各オプション定義のソースファイル位置 (definitionsWithLocations)
# を使って、宣言されたパッケージを { outPath, name, file, src } で列挙する。
#
#   system : config.environment.systemPackages の各定義 (service/desktop 由来も含む)
#   home   : 各 home-manager user の home.packages
#            (HM submodule の options は config 経由で露出しないため、
#             getSubModules + ユーザ定義モジュールを evalModules で再評価して取得する)
#
# 呼び出し (caller は --impure 必須):
#   nix eval --json --impure --expr \
#     'import .nix-ci-workflows/ci/scripts/vulnxscan_provenance.nix {
#        flakePath = "/abs/path/to/flake"; class = "nixosConfigurations"; name = "host"; }'
#
# 出力: [ { o = <outPath>; n = <name>; f = <file>; src = "system"|"home:<user>"; } ... ]
# eval が失敗しうる構成 (HM 無し等) でも壊れないよう、欠けている層は [] に縮退する。
{ flakePath, class, name }:
let
  flake = builtins.getFlake flakePath;
  cfg = flake.${class}.${name};
  # base lib は nixpkgs input から取る (nixos/darwin 両対応・cfg.pkgs 非依存)
  baseLib = flake.inputs.nixpkgs.lib;

  # definitionsWithLocations の各定義 (file + list of pkgs) を {o,n,f,src} に展開する。
  # 値が derivation (outPath を持つ attrs) のものだけ拾う。
  emit = src: defs: builtins.concatMap (
    d:
    let xs = if builtins.isList d.value then d.value else [ d.value ];
    in builtins.concatMap (
      p:
      if builtins.isAttrs p && (p.outPath or null) != null
      then [ { o = p.outPath; n = p.name or "?"; f = d.file; inherit src; } ]
      else [ ]
    ) xs
  ) defs;

  # --- system: environment.systemPackages ---
  sysRoots =
    let opt = cfg.options.environment.systemPackages or null;
    in if opt == null then [ ] else emit "system" opt.definitionsWithLocations;

  # --- home-manager: 各 user の home.packages ---
  hmUsersOpt = cfg.options.home-manager.users or null;
  hmCfg = cfg.config.home-manager or null;
  # home-manager は lib を lib.hm 付きに拡張する。再評価時はこれを渡さないと
  # 一部モジュール (mako 等) が lib.hm を参照して失敗する。
  hmExtLib =
    let
      hm = flake.inputs.home-manager or null;
      f = if hm == null then null else hm + "/modules/lib/stdlib-extended.nix";
    in if f != null && builtins.pathExists f then import f baseLib else baseLib;

  hmRootsFor = user:
    let
      subMods = hmUsersOpt.type.getSubModules;
      userDefs = builtins.concatMap (
        d: if (d.value ? ${user}) then [ d.value.${user} ] else [ ]
      ) hmUsersOpt.definitionsWithLocations;
      evaluated = hmExtLib.evalModules {
        modules = subMods ++ userDefs;
        # home-manager submoduleWith 相当の specialArgs を再現する
        # (extraSpecialArgs にユーザの inputs 等が入るため必ず引き継ぐ)。
        specialArgs = {
          osConfig = cfg.config;
          lib = hmExtLib;
          modulesPath = "";
        } // (hmCfg.extraSpecialArgs or { }) // { name = user; };
      };
    in emit "home:${user}" evaluated.options.home.packages.definitionsWithLocations;

  hmRoots =
    if hmUsersOpt == null || hmCfg == null then [ ]
    else builtins.concatMap hmRootsFor (builtins.attrNames (hmCfg.users or { }));
in
sysRoots ++ hmRoots
