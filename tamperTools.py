import sys
import os
import random
import re
import datetime
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QLabel, QComboBox,
    QFileDialog, QTextEdit, QTabWidget
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

compare_file1 = None
compare_file2 = None

app = QApplication(sys.argv)
app.setStyle('Fusion')
app.setFont(QFont('微软雅黑', 10))

window = QWidget()
window.setWindowTitle('固件篡改工具 v4.0.3')
window.setWindowIcon(QIcon("tamper.ico"))
window.resize(900, 600)

tabs = QTabWidget()

# 输出函数绑定范围中
firm_log = QTextEdit();
firm_log.setReadOnly(True)


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

mode_cb = QComboBox();
mode_cb.addItems(['flip', 'zero', 'random'])
area_cb = QComboBox();
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

# Tab 3 - 使用说明
usage_tab = QWidget()
usage_layout = QVBoxLayout(usage_tab)
usage_text = QTextEdit()
usage_text.setReadOnly(True)
usage_text.setPlainText("""工具简介:
- 本工具用于模拟固件签名区域被破坏的情景,可用于测试安全启动(Secure Boot)机制的有效性\安全升级(OTA)机制有效性.
- 支持处理多种格式的固件文件，包括.bin、.dtb、.imx和.zip(包含上述格式文件).

支持文件类型:
- 固件包 (.zip), 二进制文件 (.bin), 设备树 (.dtb), IMX 镜像 (.imx)

篡改模式:
- flip: 位翻转
- zero: 清零
- random: 随机字节

篡改区域:
- 签名区域、非签名区域、两者都篡改

操作原理:
- 识别签名偏移
- 篡改后查看日志输出
- 文件对比页面可查看不同字节

使用说明:
1. 点击"选择固件文件"，导入需要篡改的固件
2. 选择篡改模式，设置篡改次数
3. 点击"开始篡改"按钮
4. 程序会自动识别签名区域(或默认使用文件尾部区域)，并进行篡改
""")
usage_layout.addWidget(usage_text)
tabs.addTab(usage_tab, "📖 使用说明")

# 恢复窗口布局
window.setLayout(QVBoxLayout())
window.layout().addWidget(tabs)
window.show()
sys.exit(app.exec())
