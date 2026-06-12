# nix-ci-workflows

Nix CI/CD用の再利用可能なGitHub Actionsワークフロー集。

## Reusable Workflows

| ワークフロー | 説明 |
|---|---|
| `format-check.yaml` | `nix fmt -- --fail-on-change` によるフォーマットチェック |
| `discover-targets.yaml` | Flakeターゲット自動検出（NixOS/Darwin設定名、パッケージリスト） |
| `build-nix.yaml` | 単一Nixターゲットのビルド + Atticキャッシュpush（オプション） |
| `deploy-nix.yaml` | deploy-rsによるNixOSデプロイ（WireGuard VPN経由） |
| `auto-update-flake.yaml` | `nix flake update` + PR自動作成・自動マージ |

## Actions

| アクション | 説明 |
|---|---|
| `wireguard` | WireGuard VPN接続（peer-issuer API）。`post`ステップで自動teardown |

## 使用方法

### format-check

```yaml
jobs:
  format-check:
    uses: shinbunbun/nix-ci-workflows/.github/workflows/format-check.yaml@main
```

### discover-targets

```yaml
jobs:
  discover:
    uses: shinbunbun/nix-ci-workflows/.github/workflows/discover-targets.yaml@main

  build-nixos:
    needs: discover
    if: needs.discover.outputs.has-nixos == 'true'
    strategy:
      matrix: ${{ fromJSON(needs.discover.outputs.nixos-matrix) }}
    uses: shinbunbun/nix-ci-workflows/.github/workflows/build-nix.yaml@main
    with:
      runner: ubuntu-latest
      build-target: ".#nixosConfigurations.${{ matrix.configuration }}.config.system.build.toplevel"
      result-name: ${{ matrix.configuration }}
    secrets: inherit
```

### build-nix

```yaml
jobs:
  build:
    uses: shinbunbun/nix-ci-workflows/.github/workflows/build-nix.yaml@main
    with:
      runner: ubuntu-latest
      build-target: ".#nixosConfigurations.myHost.config.system.build.toplevel"
      result-name: myHost
      needs-sops: true
      needs-wireguard: false    # WireGuard不要なら公開URL経由でAttic push
      use-attic: true           # Attic連携を無効にするにはfalse
      report-closure-diff: ${{ github.ref_name != 'main' }}  # PRに closure 差分を投稿
      closure-diff-base-ref: main                            # 差分の基準ref（既定 main）
    secrets:
      ATTIC_TOKEN: ${{ secrets.ATTIC_TOKEN }}
      SOPS_AGE_KEY: ${{ secrets.SOPS_AGE_KEY }}
```

`report-closure-diff: true` のとき、ビルドした closure を `closure-diff-base-ref`
（既定 `main`）の同一ターゲット closure と `nix store diff-closures` で比較し、
対象ブランチの open PR に**ターゲット別 sticky comment**として投稿する。`pull-requests: write`
権限と `git fetch` 可能な checkout が前提。失敗してもジョブは継続する（非致命）。

### deploy-nix

```yaml
jobs:
  deploy:
    uses: shinbunbun/nix-ci-workflows/.github/workflows/deploy-nix.yaml@main
    with:
      deploy-target: ".#homeMachine"
      ssh-hostname: homemachine
      ssh-host: "192.168.1.3"
    secrets:
      AUTHENTIK_CLIENT_ID: ${{ secrets.AUTHENTIK_CLIENT_ID }}
      ATTIC_TOKEN: ${{ secrets.ATTIC_TOKEN }}
      DEPLOY_SSH_KEY: ${{ secrets.DEPLOY_SSH_KEY }}
      DISCORD_WEBHOOK_URL: ${{ secrets.DISCORD_WEBHOOK_URL }}
```

### auto-update-flake

```yaml
on:
  schedule:
    - cron: "0 2 * * *"
  workflow_dispatch:

jobs:
  update:
    uses: shinbunbun/nix-ci-workflows/.github/workflows/auto-update-flake.yaml@main
    secrets:
      PAT_TOKEN: ${{ secrets.PAT_TOKEN }}
```

## WireGuard Action

`post`ステップによる自動teardownにより、呼び出し側でteardownを明示する必要がなくなります。

```yaml
- uses: shinbunbun/nix-ci-workflows/.github/actions/wireguard@main
  with:
    authentik-client-id: ${{ secrets.AUTHENTIK_CLIENT_ID }}
# teardownは自動実行 — 明示的な呼び出し不要
```

## 必要なSecrets

| Secret | 用途 |
|---|---|
| `ATTIC_TOKEN` | Atticキャッシュへのpush用トークン |
| `ATTIC_READ_TOKEN` | Atticキャッシュからのread用トークン（省略時はATTIC_TOKENを使用） |
| `SOPS_AGE_KEY` | SOPS秘密鍵 |
| `AUTHENTIK_CLIENT_ID` | WireGuard VPN認証用 |
| `DEPLOY_SSH_KEY` | デプロイ用SSH秘密鍵 |
| `DISCORD_WEBHOOK_URL` | Discord通知用Webhook URL |
| `PAT_TOKEN` | flake更新PR作成用Personal Access Token |
