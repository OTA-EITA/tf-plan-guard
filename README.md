# tf-plan-guard

[![ci](https://github.com/OTA-EITA/tf-plan-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/OTA-EITA/tf-plan-guard/actions/workflows/ci.yml)

`terraform plan` の結果を読み、**今回の apply で実際に起きる危険な変更**を PR の段階で止める CLI です。
データの消失、削除保護の解除、インターネットへの開放、IAM のワイルドカード、公開ストレージ、暗号化なし、監査ログの停止を検出します。

A CLI that reviews a Terraform plan for risky changes before they are applied: data loss, removed deletion
protection, internet exposure, wildcard IAM, public storage, missing encryption and disabled audit logging.

## なぜ作ったか

tfsec や Checkov はコードの書き方を検査しますが、レビューで本当に知りたいのは「**この apply で何が壊れるか**」です。

- エンジンのバージョンを 1 つ変えただけで、RDS が**作り直し**（＝データ消失）になる
- モジュールの更新で、いつの間にか削除保護が `false` になる
- 既存の設定には問題がないのに、今回の変更で 22 番ポートが 0.0.0.0/0 に開く

plan の差分は長く、こうした変更は見落とされがちです。tf-plan-guard は plan の「before / after」を比べ、**今回の変更で新たに生まれるリスクだけ**を報告します。もともとある問題を毎回指摘して PR を埋めることはしません。

## ルール

| ID | 重大度 | 内容 |
|---|---|---|
| TF-DATA-001 | HIGH | データを持つリソース（RDS、DynamoDB、S3、EBS、EKS、KMS、Cloud SQL など約 30 種）の削除 |
| TF-DATA-002 | HIGH | データを持つリソースの作り直し（原因になった属性も表示） |
| TF-DATA-003 | HIGH | `deletion_protection` / `enable_deletion_protection` が true → false |
| TF-DATA-004 | MEDIUM | `skip_final_snapshot` や `force_destroy` の有効化 |
| TF-CHANGE-001 | MEDIUM | その他のリソースの削除 |
| TF-CHANGE-002 | LOW | その他のリソースの作り直し |
| TF-NET-001 | HIGH | 0.0.0.0/0 や ::/0 から、Web 以外のポートへの新たな受信許可（AWS セキュリティグループ 3 形式、GCP ファイアウォール） |
| TF-NET-002 | LOW | 0.0.0.0/0 から 80 / 443 への新たな受信許可 |
| TF-IAM-001 | HIGH | `Action: "*"` を許可するポリシー |
| TF-IAM-002 | MEDIUM | `s3:*` のようなサービス全体を `Resource: "*"` に許可 |
| TF-IAM-003 | HIGH | AdministratorAccess のアタッチ |
| TF-IAM-004 | HIGH | 条件なしで誰でも引き受けられるロール |
| TF-S3-001 | HIGH | パブリックアクセスブロックの弱体化 |
| TF-S3-002 | HIGH | 公開 ACL |
| TF-S3-003 | HIGH | 条件なしで `Principal: "*"` を許可するバケットポリシー |
| TF-DB-001 | HIGH | `publicly_accessible = true` の DB |
| TF-ENC-001 | MEDIUM | 暗号化なしで作成されるストレージ（後から有効化できない） |
| TF-AUDIT-001 | HIGH | CloudTrail・GuardDuty・Config・VPC Flow Logs などの削除や無効化 |

## 使い方

```sh
terraform plan -out plan.tfplan
terraform show -json plan.tfplan | tf-plan-guard -
```

出力例（[`e2e/risky`](e2e/risky) を本物の AWS プロバイダで plan した結果）:

```
SEVERITY  RULE        ACTION  ADDRESS                                   MESSAGE
HIGH      TF-DB-001   create  aws_db_instance.orders                    publicly_accessible is true
HIGH      TF-IAM-001  create  aws_iam_policy.deployer                   policy allows Action "*" (full administrator)
HIGH      TF-S3-001   create  aws_s3_bucket_public_access_block.assets  one or more public access block settings are false
HIGH      TF-NET-001  create  aws_security_group.bastion                opens port 22 to the internet (0.0.0.0/0 or ::/0)
MEDIUM    TF-ENC-001  create  aws_db_instance.orders                    storage_encrypted is false

Plan: 5 to add, 0 to change, 0 to destroy (0 replaced)
Findings: 4 high, 1 medium, 0 low (0 ignored)
```

`--output markdown` にすると、そのまま PR コメントに貼れる形式になります。

### 意図した変更を許可する

計画的なメジャーバージョンアップなど、意図した変更はリポジトリの `.tfplanguard-ignore` に理由と一緒に書きます。`*` はワイルドカードです。

```
# 2026-11 の PostgreSQL 16 移行。データは DMS で移行済み
TF-DATA-002 = module.db.aws_db_instance.this
# 公開 Web サーバーの 80/443 は想定どおり
TF-NET-002
```

コマンドラインの `--ignore RULE=ADDRESS_PATTERN`（複数指定可）でも指定できます。

| フラグ | 既定値 | 説明 |
|---|---|---|
| `--output` | `table` | `table` / `json` / `markdown` |
| `--fail-on` | `high` | この重大度以上で終了コード 1 |
| `--ignore` | - | `RULE=ADDRESS_PATTERN` を無視（複数指定可） |
| `--ignore-file` | `.tfplanguard-ignore` | 無視リストのファイル（既定のパスは存在しなければ無視） |
| `--list` | - | ルール一覧 |

## GitHub Actions

```yaml
- run: terraform plan -out plan.tfplan && terraform show -json plan.tfplan > plan.json
- uses: OTA-EITA/tf-plan-guard@v0.1.1
  id: guard
  with:
    plan-json: plan.json
- if: always()
  run: gh pr comment "$PR" --body-file "${{ steps.guard.outputs.report }}"
  env:
    GH_TOKEN: ${{ github.token }}
    PR: ${{ github.event.pull_request.number }}
```

結果はジョブのサマリーにも表示されます。

## インストール

[Releases](https://github.com/OTA-EITA/tf-plan-guard/releases) からバイナリをダウンロードするか、Go でインストールします。

```sh
go install github.com/OTA-EITA/tf-plan-guard/cmd/tf-plan-guard@latest
```

## テスト

- ルールごとのテーブルテスト（作成・更新・削除・作り直し、既存の問題を再指摘しないこと）
- 本物の `terraform show -json` の出力を使った CLI テスト
- CI の E2E: 危険な設定を本物の Terraform と AWS プロバイダで plan し（ダミーの認証情報で、apply はしない）、検出と無視の挙動を確認（[`e2e/run.sh`](e2e/run.sh)）

```sh
make test
make lint
```

## License

MIT
