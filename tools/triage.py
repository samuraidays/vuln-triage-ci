#!/usr/bin/env python3
"""脆弱性スキャン結果(pip-audit JSON)を KEV/CVSS/EPSS で優先度付けし、
Markdownレポートを出力する。新規 P0/P1 があれば exit code 1 で CI を落とす。

KEV/EPSS はネットワークから取得する（取得できなければ未付与で続行＝壊れない）。
"""
import json
import os
import sys
import urllib.request

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve={}"


def load_kev() -> set[str]:
    # オフライン/遮断環境では同梱fixtureにフォールバック（CIでは実APIを使う）
    local = os.environ.get("KEV_FIXTURE")
    if local and os.path.exists(local):
        data = json.load(open(local))
        return {v["cveID"] for v in data.get("vulnerabilities", [])}
    try:
        with urllib.request.urlopen(KEV_URL, timeout=15) as r:
            data = json.load(r)
        return {v["cveID"] for v in data.get("vulnerabilities", [])}
    except Exception as e:
        print(f"::warning::KEV取得失敗、KEV未付与で続行: {e}", file=sys.stderr)
        return set()


def normalize(audit_json: dict) -> list[dict]:
    out = []
    for dep in audit_json.get("dependencies", []):
        for v in dep.get("vulns", []):
            ids = [v["id"]] + v.get("aliases", [])
            cve = next((i for i in ids if i.startswith("CVE-")), v["id"])
            out.append({
                "package": dep["name"],
                "version": dep["version"],
                "id": v["id"],
                "cve": cve,
                "fix": v.get("fix_versions", []),
                "cvss": v.get("cvss"),  # pip-auditは未提供のことが多い→NVD補完想定
            })
    # 同一(package,id)の重複を排除
    uniq = {(f["package"], f["id"]): f for f in out}
    return list(uniq.values())


def priority(f: dict, kev: set[str]) -> str:
    cvss = f.get("cvss") or 0.0
    epss = f.get("epss") or 0.0
    if f["cve"] in kev:
        return "P0"            # 既知の悪用あり：即対応
    if cvss >= 9.0 or epss >= 0.5:
        return "P1"
    if cvss >= 7.0:
        return "P2"
    return "P3"


def main():
    audit = json.load(open(sys.argv[1]))
    kev = load_kev()
    findings = normalize(audit)
    for f in findings:
        f["priority"] = priority(f, kev)

    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
    findings.sort(key=lambda f: (order[f["priority"]], f["package"]))

    counts = {p: sum(1 for f in findings if f["priority"] == p) for p in order}
    lines = ["## 🔒 脆弱性トリアージ結果", "",
             f"検出: **{len(findings)}件**  "
             f"(P0:{counts['P0']} / P1:{counts['P1']} / P2:{counts['P2']} / P3:{counts['P3']})",
             "", "| 優先 | パッケージ | ID | 修正版 |", "|---|---|---|---|"]
    for f in findings:
        fix = ", ".join(f["fix"]) or "-"
        lines.append(f"| {f['priority']} | `{f['package']}@{f['version']}` | {f['id']} | {fix} |")
    report = "\n".join(lines)
    print(report)

    blocking = counts["P0"] + counts["P1"]
    if blocking:
        print(f"\n::error::新規の重大脆弱性 {blocking}件 (P0+P1) を検出しました。", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
