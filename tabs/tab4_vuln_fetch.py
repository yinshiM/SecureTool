import os, datetime, csv, requests
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextEdit, QFileDialog
)

latest_findings = []


def create_vuln_tab():
    tab = QWidget()
    layout = QVBoxLayout(tab)
    log_output = QTextEdit()
    log_output.setReadOnly(True)

    url_input = QLineEdit("http://127.0.0.1:8080")
    api_key_input = QLineEdit()
    api_key_input.setEchoMode(QLineEdit.Password)
    uuid_input = QLineEdit()

    def log(msg):
        log_output.append(msg)

    def fetch_vulns():
        base_url = url_input.text().strip()
        api_key = api_key_input.text().strip()
        project_uuid = uuid_input.text().strip()
        if not all([base_url, api_key, project_uuid]):
            log("[!] 请填写完整地址、API Key 和 UUID")
            return
        endpoint = f"{base_url}/api/v1/finding/project/{project_uuid}/export"
        headers = {"X-Api-Key": api_key}
        try:
            log(f"[*] 请求: {endpoint}")
            resp = requests.get(endpoint, headers=headers, timeout=10)
            resp.raise_for_status()
            findings = resp.json().get("findings", [])
            if not findings:
                log("[-] 未发现任何漏洞")
                return
            global latest_findings
            latest_findings = findings
            log(f"[+] 共获取 {len(findings)} 条漏洞记录")
            comp_stats = {}
            for f in findings:
                comp = f.get("component", {}).get("name", "未知组件")
                comp_stats[comp] = comp_stats.get(comp, 0) + 1
            for comp, count in comp_stats.items():
                log(f"    组件: {comp} -> 漏洞数量: {count}")
        except Exception as e:
            log(f"[!] 拉取失败: {e}")

    def export_to_csv():
        if not latest_findings:
            log("[!] 暂无漏洞信息可导出")
            return
        folder = QFileDialog.getExistingDirectory(tab, "选择导出目录")
        if not folder:
            log("[!] 已取消导出")
            return
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        out_path = os.path.join(folder, f"vulnerabilities_{ts}.csv")
        try:
            with open(out_path, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                writer.writerow(["组件", "版本", "CVE ID", "CVSS", "描述"])
                for item in latest_findings:
                    comp = item.get("component", {}).get("name", "")
                    vers = item.get("component", {}).get("version", "")
                    vuln = item.get("vulnerability", {})
                    cve = vuln.get("vulnId", "")
                    score = vuln.get("cvssV3", {}).get("baseScore", vuln.get("cvssV2", {}).get("score", ""))
                    desc = vuln.get("description", "")[:100].replace('\n', ' ')
                    writer.writerow([comp, vers, cve, score, desc])
            log(f"[+] 已保存到: {out_path}")
        except Exception as e:
            log(f"[!] 导出失败: {e}")

    # 布局区域
    url_row = QHBoxLayout()
    url_row.addWidget(QLabel("🎯 DT-Api:"))
    url_row.addWidget(url_input)

    key_row = QHBoxLayout()
    key_row.addWidget(QLabel("🔑 API-Key:"))
    key_row.addWidget(api_key_input)

    uuid_row = QHBoxLayout()
    uuid_row.addWidget(QLabel("🆔 UUID:"))
    uuid_row.addWidget(uuid_input)

    btn_row = QHBoxLayout()
    fetch_btn = QPushButton("拉取漏洞信息")
    export_btn = QPushButton("导出为 Excel")
    clear_btn = QPushButton("清除日志")
    fetch_btn.clicked.connect(fetch_vulns)
    export_btn.clicked.connect(export_to_csv)
    clear_btn.clicked.connect(log_output.clear)
    btn_row.addWidget(fetch_btn)
    btn_row.addWidget(export_btn)
    btn_row.addWidget(clear_btn)

    layout.addLayout(url_row)
    layout.addLayout(key_row)
    layout.addLayout(uuid_row)
    layout.addLayout(btn_row)
    layout.addWidget(QLabel("📋 漏洞日志输出:"))
    layout.addWidget(log_output)

    return tab
