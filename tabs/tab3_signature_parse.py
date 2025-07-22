import os, subprocess, re, zipfile
from PyQt5.QtWidgets import QFileDialog
from qfluentwidgets import (
    PushButton, LineEdit, TextEdit, TitleLabel,
    BodyLabel, SimpleCardWidget
)
from PyQt5.QtWidgets import QVBoxLayout, QHBoxLayout


def create_signature_tab():
    card = SimpleCardWidget()
    card.setObjectName("signature")  # 注册 routeKey
    layout = QVBoxLayout(card)
    layout.setContentsMargins(30, 20, 30, 20)
    layout.setSpacing(15)

    layout.addWidget(TitleLabel("签名解析与证书提取"))

    log_output = TextEdit()
    log_output.setReadOnly(True)

    def log(msg):
        log_output.append(msg)

    input_path = LineEdit()
    input_path.setPlaceholderText("拖入或选择要解析的文件路径")

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

        # 额外提取证书
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

    # 按钮和输入行
    row = QHBoxLayout()
    row.addWidget(BodyLabel("路径:"))
    row.addWidget(input_path)

    btn_select = PushButton("📂 选择文件")
    btn_select.clicked.connect(lambda: input_path.setText(QFileDialog.getOpenFileName(card, '选择文件')[0]))
    row.addWidget(btn_select)

    btn_parse = PushButton("🔍 解析+提取")
    btn_parse.clicked.connect(lambda: handle_parse_file(input_path.text().strip()))
    row.addWidget(btn_parse)

    btn_clear = PushButton("🧹 清除日志")
    btn_clear.clicked.connect(log_output.clear)
    row.addWidget(btn_clear)

    layout.addLayout(row)
    layout.addWidget(TitleLabel("解析输出"))
    layout.addWidget(log_output)

    return card
