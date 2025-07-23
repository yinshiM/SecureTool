from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QFileDialog
from qfluentwidgets import (
    TitleLabel, BodyLabel, LineEdit, PushButton, FluentIcon, TextEdit
)
import os, hashlib, csv
from zlib import crc32
from binascii import crc_hqx


def create_hash_tab():
    tab = QWidget()
    layout = QVBoxLayout(tab)
    layout.setContentsMargins(30, 20, 30, 20)
    layout.setSpacing(12)

    layout.addWidget(TitleLabel("哈希工具"))

    input_row = QHBoxLayout()
    input_label = BodyLabel("输入内容:")
    input_label.setFixedWidth(60)

    input_box = LineEdit()
    input_box.setPlaceholderText("输入字符串或选择文件")
    input_row.addWidget(input_label)
    input_row.addWidget(input_box)
    layout.addLayout(input_row)

    btn_row = QHBoxLayout()
    btn_row.setSpacing(10)

    folder_data = []

    # ✅ 使用 TextEdit 而非 QTextEdit，支持自动主题切换
    output = TextEdit()
    output.setReadOnly(True)
    output.setMinimumHeight(240)

    def append_result(text):
        output.append(text + "\n")

    def clear_output():
        input_box.clear()
        output.clear()

    def string_hash():
        text = input_box.text().strip()
        if not text:
            append_result("⚠️ 请输入字符串")
            return
        data = text.encode()
        append_result(f"🔹 字符串: {text}")
        append_result(f"  MD5: {hashlib.md5(data).hexdigest()}")
        append_result(f"  SHA1: {hashlib.sha1(data).hexdigest()}")
        append_result(f"  SHA256: {hashlib.sha256(data).hexdigest()}")
        append_result(f"  SHA384: {hashlib.sha384(data).hexdigest()}")
        append_result(f"  SHA512: {hashlib.sha512(data).hexdigest()}")
        append_result(f"  CRC32: {format(crc32(data) & 0xffffffff, '08x')}")
        append_result(f"  CRC16: {format(crc_hqx(data, 0), '04x')}")

    def file_hash():
        path, _ = QFileDialog.getOpenFileName(tab, "选择文件")
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
            append_result(f"📄 文件: {path}")
            append_result(f"  MD5: {hashlib.md5(data).hexdigest()}")
            append_result(f"  SHA1: {hashlib.sha1(data).hexdigest()}")
            append_result(f"  SHA256: {hashlib.sha256(data).hexdigest()}")
            append_result(f"  SHA384: {hashlib.sha384(data).hexdigest()}")
            append_result(f"  SHA512: {hashlib.sha512(data).hexdigest()}")
            append_result(f"  CRC32: {format(crc32(data) & 0xffffffff, '08x')}")
            append_result(f"  CRC16: {format(crc_hqx(data, 0), '04x')}")
        except Exception as e:
            append_result(f"[!] 文件处理失败: {e}")

    def folder_hash():
        nonlocal folder_data
        folder_data = []
        folder = QFileDialog.getExistingDirectory(tab, "选择文件夹")
        if not folder:
            return
        append_result(f"📁 目录: {folder}")
        for root, _, files in os.walk(folder):
            for name in files:
                fpath = os.path.join(root, name)
                try:
                    with open(fpath, "rb") as f:
                        data = f.read()
                    record = {
                        "文件名": name,
                        "路径": fpath,
                        "MD5": hashlib.md5(data).hexdigest(),
                        "SHA1": hashlib.sha1(data).hexdigest(),
                        "SHA256": hashlib.sha256(data).hexdigest(),
                        "SHA384": hashlib.sha384(data).hexdigest(),
                        "SHA512": hashlib.sha512(data).hexdigest(),
                        "CRC32": format(crc32(data) & 0xffffffff, '08x'),
                        "CRC16": format(crc_hqx(data, 0), '04x')
                    }
                    folder_data.append(record)
                    append_result(f"📄 {fpath}")
                    append_result(f"  MD5: {record['MD5']}")
                except Exception as e:
                    append_result(f"[!] 跳过失败文件 {fpath}: {e}")
        append_result(f"✅ 完成，共处理 {len(folder_data)} 个文件")

    def export_csv():
        if not folder_data:
            append_result("[!] 无文件夹哈希结果可导出")
            return
        path, _ = QFileDialog.getSaveFileName(tab, "保存 CSV", "hash_result.csv", "CSV Files (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline='', encoding='utf-8-sig') as f:
                writer = csv.DictWriter(f, fieldnames=folder_data[0].keys())
                writer.writeheader()
                writer.writerows(folder_data)
            append_result(f"[+] 已导出 CSV: {path}")
        except Exception as e:
            append_result(f"[!] 导出失败: {e}")

    btn_str = PushButton("字符串哈希", icon=FluentIcon.CODE)
    btn_str.clicked.connect(string_hash)
    btn_row.addWidget(btn_str)

    btn_file = PushButton("文件哈希", icon=FluentIcon.DOCUMENT)
    btn_file.clicked.connect(file_hash)
    btn_row.addWidget(btn_file)

    btn_folder = PushButton("批量文件夹", icon=FluentIcon.FOLDER)
    btn_folder.clicked.connect(folder_hash)
    btn_row.addWidget(btn_folder)

    btn_csv = PushButton("导出为 CSV", icon=FluentIcon.SAVE)
    btn_csv.clicked.connect(export_csv)
    btn_row.addWidget(btn_csv)

    btn_clear = PushButton("清空结果", icon=FluentIcon.BROOM)
    btn_clear.clicked.connect(clear_output)
    btn_row.addWidget(btn_clear)

    layout.addLayout(btn_row)
    layout.addWidget(BodyLabel("输出结果:"))
    layout.addWidget(output)

    return tab
