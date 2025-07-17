import os, subprocess, re, zipfile
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QLineEdit, QFileDialog
)


def create_signature_tab():
    tab = QWidget()
    layout = QVBoxLayout(tab)
    log_output = QTextEdit()
    log_output.setReadOnly(True)
    input_path = QLineEdit()
    input_path.setPlaceholderText("拖入或选择要解析的文件路径")

    def log(msg):
        log_output.append(msg)

    def handle_parse_file(path):
        if not os.path.isfile(path):
            log("[!] 文件无效")
            return
        log("[*] 使用 openssl 检查签名/证书信息...")
        log("=" * 50)
        try:
            for cmd, label in [
                (f"openssl pkcs7 -inform DER -in \"{path}\" -print_certs", "PKCS7"),
                (f"openssl x509 -inform DER -in \"{path}\" -noout -text", "X.509 DER"),
                (f"openssl x509 -in \"{path}\" -noout -text", "PEM")
            ]:
                result = subprocess.getoutput(cmd)
                if "Certificate:" in result or "BEGIN CERTIFICATE" in result:
                    log(f"[+] 检测到 {label} 格式证书:")
                    for line in result.strip().splitlines():
                        log("    " + line)
                    if label == "X.509 DER":
                        pem_out = os.path.splitext(os.path.basename(path))[0] + "_converted.pem"
                        subprocess.getoutput(f"openssl x509 -inform DER -in \"{path}\" -out \"{pem_out}\"")
                        log(f"    [+] 已转换并保存为: {pem_out}")
                else:
                    log(f"[-] 未检测到 {label} 格式证书")
        except Exception as e:
            log(f"[!] openssl 执行失败: {e}")
        log("=" * 50)

        certs = []
        try:
            from apkverify import ApkSignature
            if zipfile.is_zipfile(path):
                log("[*] Apk 文件解析开始")
                checker = ApkSignature(os.path.abspath(path))
                checker.verify(2)
                certs = checker.all_certs()
        except Exception:
            try:
                with open(path, 'rb') as f:
                    data = f.read()
                for m in re.finditer(b'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', data, re.DOTALL):
                    cert_block = m.group(0)
                    certs.append(cert_block if isinstance(cert_block, bytes) else cert_block.encode())
            except Exception as e:
                log(f"[!] bin 文件解析失败: {e}")
                return

        if not certs:
            log("[-] 未提取到任何证书")
            return

        out_dir = os.path.splitext(os.path.basename(path))[0] + "_certs"
        os.makedirs(out_dir, exist_ok=True)
        for idx, cert in enumerate(certs):
            out_path = os.path.join(out_dir, f"cert_{idx + 1}.pem")
            if isinstance(cert, str):
                cert = cert.encode('utf-8')
            with open(out_path, 'wb') as f:
                f.write(cert)
            log(f"[+] 提取证书已保存: {out_path}")
            try:
                info = subprocess.getoutput(f"openssl x509 -in \"{out_path}\" -noout -subject -issuer -dates -serial")
                log("    证书信息:")
                for line in info.strip().splitlines():
                    log("        " + line)
            except Exception as e:
                log(f"    [-] openssl 分析失败: {e}")
        log(f"[*] 共提取 {len(certs)} 个证书")

    btn_browse = QPushButton("选择文件")
    btn_browse.clicked.connect(lambda: input_path.setText(QFileDialog.getOpenFileName(tab, '选择固件文件')[0]))

    btn_parse = QPushButton("解析+提取证书")
    btn_parse.clicked.connect(
        lambda: handle_parse_file(input_path.text().strip()) if input_path.text().strip() else log(
            "[!] 请输入文件路径"))

    btn_clear = QPushButton("清除日志")
    btn_clear.clicked.connect(log_output.clear)

    top_row = QHBoxLayout()
    top_row.addWidget(QLabel("文件路径:"))
    top_row.addWidget(input_path)
    top_row.addWidget(btn_browse)
    top_row.addWidget(btn_parse)
    top_row.addWidget(btn_clear)

    layout.addLayout(top_row)
    layout.addWidget(QLabel("解析结果:"))
    layout.addWidget(log_output)

    return tab
