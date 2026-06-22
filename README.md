# vuln-triage-ci — 脅威インテリジェンス×LLMで「使える」脆弱性管理CI

GitHub Actions の無料枠だけで、コミットごとに **SBOM生成 → 脆弱性スキャン → 脅威インテリジェンス(KEV・EPSS)で優先度付け → (任意)LLM一次トリアージ → PRコメント** を回す最小サンプルです。外部の有料サービス・有料アクションは使いません。

スキャン結果をそのまま並べても数が多すぎて誰も見ません。「実際に攻撃されているか」という脅威インテリジェンスで優先度を付け、必要ならLLMで一次トリアージまで回すことで、ようやく現場で使えるCIになります。

> ⚠️ このリポジトリの `requirements.txt` は、デモのため**わざと古い（脆弱な）依存**を固定しています。動作確認用です。

## 構成

```
.
├─ requirements.txt              # デモ用にあえて古い（脆弱な）依存を固定
├─ tools/triage.py               # スキャン結果を KEV・EPSS・CVSS で優先度付け
└─ .github/workflows/security.yml
```

## 使うツール（すべて無料）

| 用途 | ツール / データ | 取得元 |
|------|----------------|--------|
| SBOM生成 (CycloneDX) | `cyclonedx-bom` | PyPI |
| 脆弱性スキャン | `pip-audit` (OSV/PyPI advisory) | PyPI |
| 優先度付け | 自作 `tools/triage.py` | 本repo |
| 脅威インテリジェンス | CISA KEV Catalog | 公開JSON（無料） |
| 脅威インテリジェンス | FIRST EPSS API | 公開API（無料） |
| 深刻度 | NVD CVSS | 公開（無料） |

> 多言語・コンテナ対象に広げる場合は `syft` + `grype`（いずれも無料OSS）に差し替え可能。`triage.py` は入力JSONのパーサだけ調整すれば再利用できます。

## ローカルで試す

```bash
pip install cyclonedx-bom pip-audit
cyclonedx-py requirements requirements.txt > sbom.cdx.json
pip-audit -r requirements.txt -f json -o findings.json --progress-spinner off || true
python tools/triage.py findings.json
```

新規に P0/P1（KEV該当 or CVSS≥9 or EPSS≥0.5）があると `triage.py` が exit 1 を返し、CIが失敗します。検出のみの P2/P3 では落としません（ノイズで開発を止めないため）。

## 優先度の付け方

| 優先 | 条件 | 意味 |
|------|------|------|
| P0 | KEVに登録あり | 実際に悪用が確認されている。即対応 |
| P1 | CVSS ≥ 9.0 または EPSS ≥ 0.5 | 重大、または悪用される見込みが高い |
| P2 | CVSS ≥ 7.0 | 深刻度は高いが緊急ではない |
| P3 | 上記以外 | 監視のみ |

## （任意）LLMによる一次トリアージ

`LLM_API_KEY` を設定すると、P0/P1 について「想定される影響・到達可能性の仮説・推奨対応」の下書きをLLMが生成し、PRコメントに添えられます。キー未設定ならこの手順はスキップされ、コアパイプラインは完全無料で完結します。出力はあくまで下書きで、最終判断は人間が行う前提です。

## コスト

- **公開リポジトリ**: GitHub Actions 無料・無制限。
- **プライベート（Freeプラン）**: Linux 2,000分/月まで無料。本ワークフローは1回あたり1〜2分程度。
- LLM一次トリアージのみ任意で費用が発生し得ます（ローカルモデルに差し替えれば無料）。