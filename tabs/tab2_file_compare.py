import os
from PyQt5.QtWidgets import QFileDialog, QHBoxLayout, QVBoxLayout
from qfluentwidgets import (
    SimpleCardWidget, PushButton, TextEdit,
    TitleLabel, BodyLabel
)

compare_file1 = None
compare_file2 = None


def create_compare_tab():
    card = SimpleCardWidget()
    layout = QVBoxLayout(card)
    layout.setContentsMargins(30, 20, 30, 20)
    layout.setSpacing(15)

    layout.addWidget(TitleLabel("文件对比功能"))

    log_output = TextEdit()
    log_output.setReadOnly(True)

    def log(msg):
        log_output.append(msg)

    def select_original_file():
        global compare_file1
        compare_file1, _ = QFileDialog.getOpenFileName(card, '选择原始文件')
        if compare_file1:
            log(f"[*] 原始文件: {compare_file1}")

    def select_tampered_file():
        global compare_file2
        compare_file2, _ = QFileDialog.getOpenFileName(card, '选择篡改文件')
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

    row = QHBoxLayout()
    row.addWidget(PushButton("📂 原始文件", card))
    row.itemAt(0).widget().clicked.connect(select_original_file)
    row.addWidget(PushButton("📝 篡改文件", card))
    row.itemAt(1).widget().clicked.connect(select_tampered_file)
    row.addWidget(PushButton("🔍 对比差异", card))
    row.itemAt(2).widget().clicked.connect(compare_files)
    row.addWidget(PushButton("🧹 清除日志", card))
    row.itemAt(3).widget().clicked.connect(log_output.clear)

    layout.addLayout(row)
    layout.addWidget(TitleLabel("日志输出"))
    layout.addWidget(log_output)

    return card
