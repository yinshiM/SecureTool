import os, random, datetime, re
from PyQt5.QtWidgets import QVBoxLayout, QHBoxLayout, QFileDialog
from qfluentwidgets import (
    LineEdit, ComboBox, PushButton, TextEdit,
    SimpleCardWidget, BodyLabel, TitleLabel
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
    card = SimpleCardWidget()
    layout = QVBoxLayout(card)
    layout.setContentsMargins(30, 20, 30, 20)
    layout.setSpacing(15)

    layout.addWidget(TitleLabel("固件篡改功能"))

    log_output = TextEdit()
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

    file_input = LineEdit()
    file_input.setPlaceholderText("固件文件路径")

    btn_browse = PushButton("📂 选择文件")
    btn_browse.clicked.connect(lambda: file_input.setText(
        QFileDialog.getOpenFileName(card, '选择固件', '', '固件 (*.bin *.zip *.dtb *.imx)')[0]))

    mode_cb = ComboBox()
    mode_cb.addItems(['flip', 'zero', 'random'])

    area_cb = ComboBox()
    area_cb.addItems(['签名区域', '非签名区域', '两者都篡改'])

    times_input = LineEdit()
    times_input.setText("1")

    btn_start = PushButton("🚀 开始篡改")
    btn_start.clicked.connect(lambda: tamper_firmware(
        file_input.text(), mode_cb.currentText(), int(times_input.text()), area_cb.currentText()))

    btn_clear = PushButton("🧹 清除日志")
    btn_clear.clicked.connect(log_output.clear)

    row1 = QHBoxLayout()
    row1.addWidget(BodyLabel("路径:"))
    row1.addWidget(file_input)
    row1.addWidget(btn_browse)

    row2 = QHBoxLayout()
    row2.addWidget(BodyLabel("模式:"))
    row2.addWidget(mode_cb)
    row2.addWidget(BodyLabel("区域:"))
    row2.addWidget(area_cb)
    row2.addWidget(BodyLabel("次数:"))
    row2.addWidget(times_input)
    row2.addWidget(btn_start)
    row2.addWidget(btn_clear)

    layout.addLayout(row1)
    layout.addLayout(row2)
    layout.addWidget(TitleLabel("日志输出"))
    layout.addWidget(log_output)

    return card
