import hashlib
import os
import csv
from zlib import crc32
from binascii import crc_hqx
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QTextEdit, QFileDialog, QGroupBox
)


def create_hash_tab():
    tab = QWidget()
    layout = QVBoxLayout(tab)

    input_text = QLineEdit()
    input_text.setPlaceholderText("输入字符串或选择文件")

    result_output = QTextEdit()
    result_output.setReadOnly(True)
    result_output.setFixedHeight(300)

    hash_a = QLineEdit()
    hash_a.setPlaceholderText("哈希值 A")
    hash_b = QLineEdit()
    hash_b.setPlaceholderText("哈希值 B")
    compare_result = QTextEdit()
    compare_result.setReadOnly(True)
    compare_result.setFixedHeight(100)

    folder_hash_data = []

    def show_result(title, content):
        result_output.append(f"【{title}】\n{content}\n")

    def clear_all():
        input_text.clear()
        result_output.clear()
        hash_a.clear()
        hash_b.clear()
        compare_result.clear()

    def calc_hash():
        txt = input_text.text()
        if not txt:
            return
        try:
            btxt = txt.encode()
            result_output.append(f"🔹 字符串: {txt}")
            result_output.append(f"  MD5: {hashlib.md5(btxt).hexdigest()}")
            result_output.append(f"  SHA1: {hashlib.sha1(btxt).hexdigest()}")
            result_output.append(f"  SHA256: {hashlib.sha256(btxt).hexdigest()}")
            result_output.append(f"  SHA384: {hashlib.sha384(btxt).hexdigest()}")
            result_output.append(f"  SHA512: {hashlib.sha512(btxt).hexdigest()}")
            result_output.append(f"  CRC32: {format(crc32(btxt) & 0xffffffff, '08x')}")
            result_output.append(f"  CRC16: {format(crc_hqx(btxt, 0), '04x')}")
        except Exception as e:
            show_result("错误", str(e))

    def calc_file_hash():
        path, _ = QFileDialog.getOpenFileName(tab, "选择文件", "", "All Files (*)")
        if not path:
            return
        try:
            with open(path, 'rb') as f:
                data = f.read()
            result_output.append(f"📄 文件: {path}")
            result_output.append(f"  MD5: {hashlib.md5(data).hexdigest()}")
            result_output.append(f"  SHA1: {hashlib.sha1(data).hexdigest()}")
            result_output.append(f"  SHA256: {hashlib.sha256(data).hexdigest()}")
            result_output.append(f"  SHA384: {hashlib.sha384(data).hexdigest()}")
            result_output.append(f"  SHA512: {hashlib.sha512(data).hexdigest()}")
            result_output.append(f"  CRC32: {format(crc32(data) & 0xffffffff, '08x')}")
            result_output.append(f"  CRC16: {format(crc_hqx(data, 0), '04x')}")
        except Exception as e:
            show_result("错误", str(e))

    def compare_hash():
        a, b = hash_a.text().strip().lower(), hash_b.text().strip().lower()
        if not a or not b:
            compare_result.setText("请填写两个哈希值进行比较")
            return
        diff = []
        for i, (x, y) in enumerate(zip(a, b)):
            if x != y:
                diff.append(f"位置 {i}: {x} ≠ {y}")
        if len(a) != len(b):
            diff.append(f"长度不同: A={len(a)}，B={len(b)}")
        compare_result.setText("\n".join(diff) if diff else "两个哈希值完全一致")

    def calc_folder_hash():
        nonlocal folder_hash_data
        folder_hash_data = []
        folder = QFileDialog.getExistingDirectory(tab, "选择文件夹")
        if not folder:
            return
        result_output.append(f"📁 目录: {folder}")
        for root, _, files in os.walk(folder):
            for name in files:
                fpath = os.path.join(root, name)
                try:
                    with open(fpath, 'rb') as f:
                        data = f.read()
                    record = {
                        "文件名": name,
                        "完整路径": fpath,
                        "MD5": hashlib.md5(data).hexdigest(),
                        "SHA1": hashlib.sha1(data).hexdigest(),
                        "SHA256": hashlib.sha256(data).hexdigest(),
                        "SHA384": hashlib.sha384(data).hexdigest(),
                        "SHA512": hashlib.sha512(data).hexdigest(),
                        "CRC32": format(crc32(data) & 0xffffffff, '08x'),
                        "CRC16": format(crc_hqx(data, 0), '04x')
                    }
                    folder_hash_data.append(record)
                    result_output.append(f"\n📄 {fpath}")
                    result_output.append(f"  MD5: {record['MD5']}")
                    result_output.append(f"  SHA1: {record['SHA1']}")
                    result_output.append(f"  SHA256: {record['SHA256']}")
                    result_output.append(f"  SHA384: {record['SHA384']}")
                    result_output.append(f"  SHA512: {record['SHA512']}")
                    result_output.append(f"  CRC32: {record['CRC32']}")
                    result_output.append(f"  CRC16: {record['CRC16']}")

                except Exception as e:
                    result_output.append(f"[!] 处理失败: {fpath} - {e}")
        result_output.append(f"\n[✔] 共处理 {len(folder_hash_data)} 个文件")

    def export_folder_hash():
        if not folder_hash_data:
            result_output.append("[!] 暂无文件夹哈希数据可导出")
            return
        out_path, _ = QFileDialog.getSaveFileName(tab, "保存CSV", "folder_hashes.csv", "CSV Files (*.csv)")
        if not out_path:
            return
        try:
            with open(out_path, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.DictWriter(f, fieldnames=folder_hash_data[0].keys())
                writer.writeheader()
                writer.writerows(folder_hash_data)
            result_output.append(f"[+] 已导出: {out_path}")
        except Exception as e:
            result_output.append(f"[!] 导出失败: {e}")

    # 输入区域
    input_layout = QHBoxLayout()
    input_layout.addWidget(QPushButton("字符串哈希", clicked=calc_hash))
    input_layout.addWidget(QPushButton("选择文件哈希", clicked=calc_file_hash))
    input_layout.addWidget(QPushButton("文件夹批量哈希", clicked=calc_folder_hash))
    input_layout.addWidget(QPushButton("导出为CSV", clicked=export_folder_hash))

    # 比对区域
    compare_box = QGroupBox("哈希比对")
    compare_layout = QVBoxLayout(compare_box)
    compare_layout.addWidget(hash_a)
    compare_layout.addWidget(hash_b)
    compare_layout.addWidget(QPushButton("比对哈希值", clicked=compare_hash))
    compare_layout.addWidget(compare_result)

    layout.addWidget(QLabel("输入内容:"))
    layout.addWidget(input_text)
    layout.addLayout(input_layout)
    layout.addWidget(QLabel("输出结果:"))
    layout.addWidget(result_output)
    layout.addWidget(compare_box)
    layout.addWidget(QPushButton("清除所有", clicked=clear_all))

    return tab
