import os
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QFileDialog
)

compare_file1 = None
compare_file2 = None


def create_compare_tab():
    tab = QWidget()
    layout = QVBoxLayout(tab)
    log_output = QTextEdit()
    log_output.setReadOnly(True)

    def log(msg):
        log_output.append(msg)

    def select_original_file():
        global compare_file1
        compare_file1, _ = QFileDialog.getOpenFileName(tab, '选择原始文件')
        if compare_file1:
            log(f"[*] 原始文件: {compare_file1}")

    def select_tampered_file():
        global compare_file2
        compare_file2, _ = QFileDialog.getOpenFileName(tab, '选择篡改文件')
        if compare_file2:
            log(f"[*] 篡改文件: {compare_file2}")

    def compare_files():
        if not compare_file1 or not compare_file2:
            log("[!] 请先选择两个文件")
            return
        try:
            with open(compare_file1, 'rb') as f1, open(compare_file2, 'rb') as f2:
                d1 = f1.read()
                d2 = f2.read()
            diffs = [(i, d1[i], d2[i]) for i in range(min(len(d1), len(d2))) if d1[i] != d2[i]][:20]
            log(f"[+] 文件对比结果，共发现 {len(diffs)} 处不同 (最多显示前20条):")
            for idx, (off, b1, b2) in enumerate(diffs):
                log(f"    差异#{idx + 1}: 偏移0x{off:X}, 原始0x{b1:02X} -> 篡改0x{b2:02X}")
        except Exception as e:
            log(f"[!] 对比失败: {e}")

    btn_orig = QPushButton("选择原始文件")
    btn_orig.clicked.connect(select_original_file)

    btn_tamp = QPushButton("选择篡改文件")
    btn_tamp.clicked.connect(select_tampered_file)

    btn_cmp = QPushButton("对比文件差异")
    btn_cmp.clicked.connect(compare_files)

    btn_clr = QPushButton("清除日志")
    btn_clr.clicked.connect(log_output.clear)

    hbox = QHBoxLayout()
    hbox.addWidget(btn_orig)
    hbox.addWidget(btn_tamp)
    hbox.addWidget(btn_cmp)
    hbox.addWidget(btn_clr)

    layout.addLayout(hbox)
    layout.addWidget(QLabel("日志输出:"))
    layout.addWidget(log_output)

    return tab
