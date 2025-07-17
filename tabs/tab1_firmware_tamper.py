import os, random, datetime, re
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QTextEdit, QComboBox, QFileDialog
)

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


def create_firmware_tab():
    tab = QWidget()
    layout = QVBoxLayout(tab)
    log_output = QTextEdit()
    log_output.setReadOnly(True)

    def log(msg):
        log_output.append(msg)

    def find_signature_area(file_path):
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            matches = []
            log("[*] 开始签名区域扫描 (模拟 binwalk)...\n" + "=" * 50)
            log(f"{'Offset':>10}    类型描述\n" + "=" * 50)
            for pattern, desc in SIGNATURE_PATTERNS:
                for match in re.finditer(re.escape(pattern), data):
                    offset = match.start()
                    matches.append((offset, desc))
                    log(f"0x{offset:08X}    {desc}")
            if matches:
                matches.sort(key=lambda x: x[0])
                offset = matches[0][0]
                log("=" * 50)
                log(f"[+] 在偏移 0x{offset:X} 发现签名区域: {matches[0][1]}")
                return offset
            else:
                offset = len(data) - 512
                log("=" * 50)
                log(f"[!] 未发现签名区域，使用末尾 512 字节: 0x{offset:X}")
                return offset
        except Exception as e:
            log(f"[!] 签名区域扫描失败: {e}")
            return 0

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
        sig_off = find_signature_area(path)
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

    file_input = QLineEdit()
    btn_browse = QPushButton("📂 选择文件")
    btn_browse.clicked.connect(lambda: file_input.setText(
        QFileDialog.getOpenFileName(tab, '选择固件', '', '固件 (*.bin *.zip *.dtb *.imx)')[0]))

    mode_cb = QComboBox()
    mode_cb.addItems(['flip', 'zero', 'random'])

    area_cb = QComboBox()
    area_cb.addItems(['签名区域', '非签名区域', '两者都篡改'])

    times_input = QLineEdit('1')

    btn_start = QPushButton("🚀 开始篡改")
    btn_start.clicked.connect(
        lambda: tamper_firmware(file_input.text(), mode_cb.currentText(), int(times_input.text()),
                                area_cb.currentText()))

    btn_clear = QPushButton("清除日志")
    btn_clear.clicked.connect(log_output.clear)

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

    layout.addLayout(hbox1)
    layout.addLayout(hbox2)
    layout.addWidget(QLabel("日志输出:"))
    layout.addWidget(log_output)

    return tab
