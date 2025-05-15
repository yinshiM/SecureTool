import csv
import sys
import os
import random
import re
import datetime
import subprocess
import zipfile
import requests
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QLabel, QComboBox,
    QFileDialog, QTextEdit, QTabWidget
)

app = QApplication(sys.argv)
app.setStyle('Fusion')
app.setFont(QFont('微软雅黑', 10))

window = QWidget()
window.setWindowTitle('安全工具 v4.1')
window.setWindowIcon(QIcon("tamper.ico"))
window.resize(900, 600)

tabs = QTabWidget()

# 固件篡改日志输出框
firm_log = QTextEdit()
firm_log.setReadOnly(True)

SIGNATURE_PATTERNS = [
    (b'\x30\x82', 'X.509证书头'),
    (b'\x30\x80', 'PKCS#7签名'),
    (b'\x30\x81\x9F', 'RSA公钥'),
    (b'\xA0\x03\x02\x01', 'SHA哈希'),
    (b'\x06\x09\x2A\x86\x48', 'ASN.1 OID'),
    (b'-----BEGIN CERTIFICATE-----', 'PEM证书'),
    (b'-----BEGIN PUBLIC KEY-----', 'PEM公钥'),
    (b'-----BEGIN RSA', 'PEM RSA密钥'),
    (b'\xD0\x0D\xFE\xED', 'DTB魔术字节'),
    (b'\x27\x05\x19\x56', 'IMX魔术字节'),
]

compare_file1 = None
compare_file2 = None


def log(msg):
    firm_log.append(msg)


def find_signature_area(file_path, log_func=None):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        matches = []
        if log_func:
            log_func("[*] 开始签名区域扫描 (模拟 binwalk)...")
            log_func("=" * 50)
            log_func(f"{'Offset':>10}    类型描述")
            log_func("=" * 50)
        for pattern, desc in SIGNATURE_PATTERNS:
            for match in re.finditer(re.escape(pattern), data):
                offset = match.start()
                matches.append((offset, desc))
                if log_func:
                    log_func(f"0x{offset:08X}    {desc}")
        if matches:
            matches.sort(key=lambda x: x[0])
            offset = matches[0][0]
            if log_func:
                log_func("=" * 50)
                log_func(f"[+] 在偏移 0x{offset:X} 发现签名区域: {matches[0][1]}")
            return offset
        else:
            offset = len(data) - 512
            if log_func:
                log_func("=" * 50)
                log_func(f"[!] 未发现明显签名区域，使用末尾 512 字节作为签名区域: 0x{offset:X}")
            return offset
    except Exception as e:
        if log_func:
            log_func(f"[!] 签名区域扫描失败: {e}")
        return len(data) - 512


def tamper_data(data, offset, size, mode, times):
    for _ in range(times):
        pos = offset + random.randint(0, size - 1)
        original = data[pos]
        if mode == 'flip':
            data[pos] ^= 0xFF
        elif mode == 'zero':
            data[pos] = 0x00
        elif mode == 'random':
            data[pos] = random.randint(0, 255)
        log(f"    [+] 篡改偏移 0x{pos:X}: 0x{original:02X} -> 0x{data[pos]:02X}")


def tamper_firmware(path, mode, times, area):
    if not os.path.isfile(path):
        log("[!] 文件无效")
        return
    log(f"[*] 处理文件: {path}")
    with open(path, 'rb') as f:
        data = bytearray(f.read())
    sig_off = find_signature_area(path, log)
    if area == '签名区域':
        tamper_data(data, sig_off, len(data) - sig_off, mode, times)
    elif area == '非签名区域':
        tamper_data(data, 0, sig_off, mode, times)
    else:
        tamper_data(data, 0, sig_off, mode, times)
        tamper_data(data, sig_off, len(data) - sig_off, mode, times)
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    out_path = f"{os.path.splitext(path)[0]}_tampered_{ts}{os.path.splitext(path)[1]}"
    with open(out_path, 'wb') as f:
        f.write(data)
    log(f"[+] 已保存: {out_path}")


# Tab 1 - 固件篡改
tab1 = QWidget()
layout1 = QVBoxLayout(tab1)

file_input = QLineEdit()
btn_browse = QPushButton("📂 选择文件")
btn_browse.clicked.connect(lambda: file_input.setText(
    QFileDialog.getOpenFileName(window, '选择固件', '', '固件 (*.bin *.zip *.dtb *.imx)')[0]))

mode_cb = QComboBox()
mode_cb.addItems(['flip', 'zero', 'random'])
area_cb = QComboBox()
area_cb.addItems(['签名区域', '非签名区域', '两者都篡改'])
times_input = QLineEdit('1')
btn_start = QPushButton("🚀 开始篡改")
btn_start.clicked.connect(
    lambda: tamper_firmware(file_input.text(), mode_cb.currentText(), int(times_input.text()), area_cb.currentText()))
btn_clear = QPushButton("清除日志")
btn_clear.clicked.connect(firm_log.clear)

hbox1 = QHBoxLayout()
hbox1.addWidget(QLabel("文件路径:"))
hbox1.addWidget(file_input)
hbox1.addWidget(btn_browse)

hbox2 = QHBoxLayout()
hbox2.addWidget(QLabel("篡改模式:"))
hbox2.addWidget(mode_cb)
hbox2.addWidget(QLabel("篡改区域:"))
hbox2.addWidget(area_cb)
hbox2.addWidget(QLabel("次数:"))
hbox2.addWidget(times_input)
hbox2.addWidget(btn_start)
hbox2.addWidget(btn_clear)

layout1.addLayout(hbox1)
layout1.addLayout(hbox2)
layout1.addWidget(QLabel("日志输出:"))
layout1.addWidget(firm_log)

tabs.addTab(tab1, "固件篡改")

# Tab 2 - 文件对比
compare_log = QTextEdit();
compare_log.setReadOnly(True)


def select_original_file():
    global compare_file1
    compare_file1, _ = QFileDialog.getOpenFileName(window, '选择原始文件')
    if compare_file1:
        compare_log.append(f"[*] 原始文件: {compare_file1}")


def select_tampered_file():
    global compare_file2
    compare_file2, _ = QFileDialog.getOpenFileName(window, '选择篡改文件')
    if compare_file2:
        compare_log.append(f"[*] 篡改文件: {compare_file2}")


def compare_files():
    if not compare_file1 or not compare_file2:
        compare_log.append("[!] 请先选择两个文件")
        return
    try:
        with open(compare_file1, 'rb') as f1, open(compare_file2, 'rb') as f2:
            d1 = f1.read()
            d2 = f2.read()
        diffs = [(i, d1[i], d2[i]) for i in range(min(len(d1), len(d2))) if d1[i] != d2[i]][:20]
        compare_log.append(f"[+] 文件对比结果，共发现 {len(diffs)} 处不同 (最多显示前20条):")
        for idx, (off, b1, b2) in enumerate(diffs):
            compare_log.append(f"    差异#{idx + 1}: 偏移0x{off:X}, 原始0x{b1:02X} -> 篡改0x{b2:02X}")
    except Exception as e:
        compare_log.append(f"[!] 对比失败: {e}")


tab2 = QWidget()
layout2 = QVBoxLayout(tab2)

btn_orig = QPushButton("选择原始文件")
btn_orig.clicked.connect(select_original_file)
btn_tamp = QPushButton("选择篡改文件")
btn_tamp.clicked.connect(select_tampered_file)
btn_cmp = QPushButton("对比文件差异")
btn_cmp.clicked.connect(compare_files)
btn_clr = QPushButton("清除日志")
btn_clr.clicked.connect(compare_log.clear)

hbox_cmp = QHBoxLayout()
hbox_cmp.addWidget(btn_orig)
hbox_cmp.addWidget(btn_tamp)
hbox_cmp.addWidget(btn_cmp)
hbox_cmp.addWidget(btn_clr)

layout2.addLayout(hbox_cmp)
layout2.addWidget(QLabel("日志输出:"))
layout2.addWidget(compare_log)

tabs.addTab(tab2, "文件对比")

# Tab 3 - 签名解析
parse_tab = QWidget()
parse_layout = QVBoxLayout(parse_tab)
parse_log = QTextEdit()
parse_log.setReadOnly(True)
parse_input = QLineEdit()
parse_input.setPlaceholderText("拖入或选择要解析的文件路径")

parse_btn = QPushButton("选择文件")
parse_btn.clicked.connect(lambda: parse_input.setText(QFileDialog.getOpenFileName(None, '选择固件文件')[0]))

parse_start_btn = QPushButton("解析+提取证书")
parse_start_btn.clicked.connect(
    lambda: handle_parse_file(parse_input.text()) if parse_input.text() else parse_log.append("[!] 请输入文件路径"))

parse_clear_btn = QPushButton("清除日志")
parse_clear_btn.clicked.connect(parse_log.clear)

parse_top = QHBoxLayout()
parse_top.addWidget(QLabel("文件路径:"))
parse_top.addWidget(parse_input)
parse_top.addWidget(parse_btn)
parse_top.addWidget(parse_start_btn)
parse_top.addWidget(parse_clear_btn)  # ✅ 加到同一行

parse_layout.addLayout(parse_top)
parse_layout.addWidget(QLabel("解析结果:"))
parse_layout.addWidget(parse_log)


def handle_parse_file(path):
    if not os.path.isfile(path):
        parse_log.append("[!] 文件无效")
        return
    parse_log.append("[*] 使用 openssl 检查签名/证书信息...");
    parse_log.append("=" * 50)
    try:
        for cmd, label in [
            (f"openssl pkcs7 -inform DER -in \"{path}\" -print_certs", "PKCS7"),
            (f"openssl x509 -inform DER -in \"{path}\" -noout -text", "X.509 DER"),
            (f"openssl x509 -in \"{path}\" -noout -text", "PEM")
        ]:
            result = subprocess.getoutput(cmd)
            if "Certificate:" in result or "BEGIN CERTIFICATE" in result:
                parse_log.append(f"[+] 检测到 {label} 格式证书:")
                for line in result.strip().splitlines():
                    parse_log.append("    " + line)
                if label == "X.509 DER":
                    pem_out = os.path.splitext(os.path.basename(path))[0] + "_converted.pem"
                    subprocess.getoutput(f"openssl x509 -inform DER -in \"{path}\" -out \"{pem_out}\"")
                    parse_log.append(f"    [+] 已转换并保存为: {pem_out}")
            else:
                parse_log.append(f"[-] 未检测到 {label} 格式证书")
    except Exception as e:
        parse_log.append(f"[!] openssl 执行失败: {e}")
    parse_log.append("=" * 50)
    certs = []
    try:
        from apkverify import ApkSignature
        if zipfile.is_zipfile(path):
            parse_log.append("[*] Apk 文件解析开始")
            checker = ApkSignature(os.path.abspath(path))
            checker.verify(2)
            parse_log.append("[*] 调用 checker.all_certs()")
            certs = checker.all_certs()
            if not certs:
                parse_log.append("[-] 未提取到任何证书")
                return
        else:
            raise ValueError("不是 ZIP 格式，尝试 bin 提取")
    except Exception:
        try:
            parse_log.append("[*] 尝试在二进制文件中提取证书片段")
            with open(path, 'rb') as f:
                data = f.read()
            for m in re.finditer(b'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', data, re.DOTALL):
                cert_block = m.group(0)
                certs.append(cert_block if isinstance(cert_block, bytes) else cert_block.encode())
            if not certs:
                parse_log.append("[-] 未在 bin 文件中找到 PEM 格式证书")
                return
        except Exception as e:
            parse_log.append(f"[!] bin 解析失败: {e}")
            return
    if not certs:
        parse_log.append("[-] 未提取到任何证书")
        return
    out_dir = os.path.splitext(os.path.basename(path))[0] + "_certs"
    os.makedirs(out_dir, exist_ok=True)
    for idx, cert in enumerate(certs):
        out_path = os.path.join(out_dir, f"cert_{idx + 1}.pem")
        if isinstance(cert, str):
            cert = cert.encode('utf-8')
        with open(out_path, 'wb') as f:
            f.write(cert)
        parse_log.append(f"[+] 提取证书已保存: {out_path}")
        try:
            info = subprocess.getoutput(f"openssl x509 -in \"{out_path}\" -noout -subject -issuer -dates -serial")
            parse_log.append("    证书信息:")
            for line in info.strip().splitlines():
                parse_log.append("        " + line)
        except Exception as e:
            parse_log.append(f"    [-] openssl 分析失败: {e}")
    parse_log.append(f"[*] 共提取 {len(certs)} 个证书")


tabs.addTab(parse_tab, "签名解析")

# Tab 4 - 组件漏洞提取

vuln_tab = QWidget()
vuln_layout = QVBoxLayout(vuln_tab)
vuln_log = QTextEdit()
vuln_log.setReadOnly(True)

# 输入框初始化
url_input = QLineEdit("http://172.16.3.78:8080")
api_key_input = QLineEdit("odt_DJItqXDqQlxk4X9bVSFJXak2lGIDNofu")
api_key_input.setEchoMode(QLineEdit.Password)
uuid_input = QLineEdit()
uuid_input.setPlaceholderText("项目 UUID")

# 设置统一输入框宽度（可选）
url_input.setMinimumWidth(500)
api_key_input.setMinimumWidth(500)
uuid_input.setMinimumWidth(500)

# Label 宽度统一
label_width = 130

lbl_url = QLabel("🎯 DT-Api:")
lbl_url.setFixedWidth(label_width)

lbl_key = QLabel("🔑 API-Key:")
lbl_key.setFixedWidth(label_width)

lbl_uuid = QLabel("🆔 UUID:")
lbl_uuid.setFixedWidth(label_width)

# 分行布局
url_row = QHBoxLayout()
url_row.addWidget(lbl_url)
url_row.addWidget(url_input)

key_row = QHBoxLayout()
key_row.addWidget(lbl_key)
key_row.addWidget(api_key_input)

uuid_row = QHBoxLayout()
uuid_row.addWidget(lbl_uuid)
uuid_row.addWidget(uuid_input)


def fetch_vulns():
    base_url = url_input.text().strip()
    api_key = api_key_input.text().strip()
    project_uuid = uuid_input.text().strip()
    if not all([base_url, api_key, project_uuid]):
        vuln_log.append("[!] 请填写完整地址、API Key 和 UUID")
        return
    endpoint = f"{base_url}/api/v1/finding/project/{project_uuid}/export"
    headers = {"X-Api-Key": api_key}
    try:
        vuln_log.append(f"[*] 请求: {endpoint}")
        resp = requests.get(endpoint, headers=headers, timeout=10)
        resp.raise_for_status()
        findings = resp.json().get("findings", [])
        if not findings:
            vuln_log.append("[-] 未发现任何漏洞")
            return
        global latest_findings
        latest_findings = findings
        vuln_log.append(f"[+] 共获取 {len(findings)} 条漏洞记录")
        comp_stats = {}
        for finding in findings:
            comp = finding.get("component", {}).get("name", "未知组件")
            comp_stats[comp] = comp_stats.get(comp, 0) + 1
        for comp, count in comp_stats.items():
            vuln_log.append(f"    组件: {comp} -> 漏洞数量: {count}")
    except Exception as e:
        vuln_log.append(f"[!] 拉取失败: {e}")


def export_to_csv():
    if not latest_findings:
        vuln_log.append("[!] 暂无漏洞信息可导出")
        return

    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    folder = QFileDialog.getExistingDirectory(None, "选择导出目录")
    if not folder:
        vuln_log.append("[!] 已取消导出")
        return

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
        vuln_log.append(f"[+] 已保存到: {out_path}")
    except Exception as e:
        vuln_log.append(f"[!] 导出失败: {e}")


# 按钮布局
btn_row = QHBoxLayout()
fetch_btn = QPushButton("拉取漏洞信息")
export_btn = QPushButton("导出为 Excel")
clear_btn = QPushButton("清除日志")
btn_row.addWidget(fetch_btn)
btn_row.addWidget(export_btn)
btn_row.addWidget(clear_btn)

fetch_btn.clicked.connect(fetch_vulns)
export_btn.clicked.connect(export_to_csv)
clear_btn.clicked.connect(vuln_log.clear)

# 添加到主布局
vuln_layout.addLayout(url_row)
vuln_layout.addLayout(key_row)
vuln_layout.addLayout(uuid_row)
vuln_layout.addLayout(btn_row)
vuln_layout.addWidget(QLabel("📋 漏洞日志输出:"))
vuln_layout.addWidget(vuln_log)

tabs.addTab(vuln_tab, "组件漏洞提取")

# Tab 5 - 使用说明
usage_tab = QWidget()
usage_layout = QVBoxLayout(usage_tab)
usage_text = QTextEdit()
usage_text.setReadOnly(True)
usage_text.setPlainText("""工具简介:
- 本工具用于模拟固件签名区域被破坏的情景,可用于测试安全启动(Secure Boot)机制的有效性、安全升级(OTA)机制有效性。
- 支持处理多种格式的固件文件，包括.bin、.dtb、.imx和.zip(包含上述格式文件)。
- 支持Dependency-Track平台漏洞信息获取。

支持文件类型:
- 固件包 (.zip), 二进制文件 (.bin), 设备树 (.dtb), IMX 镜像 (.imx)

篡改模式:
- flip: 位翻转
- zero: 清零
- random: 随机字节

篡改区域:
- 签名区域、非签名区域、两者都篡改

操作说明:
1. 点击"选择固件文件"，导入需要篡改的固件
2. 选择篡改模式，设置篡改次数
3. 点击"开始篡改"按钮
4. 程序会自动识别签名区域(或默认使用文件尾部区域)，并进行篡改

漏洞信息获取操作说明:
1.填写相应任务UUID，点击漏洞信息获取可获得漏洞统计。
2.点击保存为Excel表格可导出漏洞信息到表格。
""")
usage_layout.addWidget(usage_text)
tabs.addTab(usage_tab, "📖 使用说明")

window.setLayout(QVBoxLayout())
window.layout().addWidget(tabs)
window.show()
sys.exit(app.exec())
