import os
import re
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QLineEdit, QFileDialog, QComboBox, QMessageBox
)

# 常用编码列表（用于自动尝试或手动选择）
COMMON_ENCODINGS = [
    "utf-8", "gbk", "gb2312", "latin1", "utf-16", "utf-32", "ascii", "big5"
]


def extract_clean_bytes(hex_text: str) -> bytes:
    import re
    segments = re.findall(r'(?:[0-9a-fA-F]{2}[ \t]*){4,}', hex_text)
    hex_bytes = []
    for seg in segments:
        hex_bytes += re.findall(r'[0-9a-fA-F]{2}', seg)
    raw = bytes(int(b, 16) for b in hex_bytes)

    try:
        decoded = raw.decode("utf-8", errors="ignore")
    except UnicodeDecodeError:
        decoded = raw.decode("latin1", errors="ignore")

    # 过滤：只保留 ASCII 可见字符 + 换行（0x0A）和回车（0x0D）
    filtered = ''.join(c for c in decoded if (32 <= ord(c) <= 126 or c in '\r\n'))

    return filtered.encode("utf-8")


def score_text_readability(text: str) -> int:
    """简单评分：统计可见字符比例"""
    return sum(c.isprintable() for c in text)


def create_hex_tab():
    tab = QWidget()
    layout = QVBoxLayout(tab)

    # 输入控件
    hex_input = QTextEdit()
    hex_input.setPlaceholderText("可粘贴包含 HEX 字符的文本，支持空格或无空格格式")
    hex_log = QTextEdit();
    hex_log.setReadOnly(True)
    hex_result = QTextEdit();
    hex_result.setReadOnly(True)
    encoding_box = QComboBox();
    encoding_box.addItems(COMMON_ENCODINGS);
    encoding_box.setCurrentText("utf-8")

    def parse_input():
        content = hex_input.toPlainText()
        if not content.strip():
            hex_log.append("[!] 请输入HEX字符串或打开文件")
            return
        raw_bytes = extract_clean_bytes(content)
        best_text, best_encoding, best_score = "", "", -1
        all_results = []

        for enc in COMMON_ENCODINGS:
            try:
                decoded = raw_bytes.decode(enc, errors="ignore")
                score = score_text_readability(decoded)
                all_results.append((enc, score, decoded))
                if score > best_score:
                    best_score = score
                    best_encoding = enc
                    best_text = decoded
            except:
                continue

        # 更新输出
        encoding_box.setCurrentText(best_encoding)
        hex_result.setPlainText(best_text)
        hex_log.append(f"[+] 自动选择最优编码: {best_encoding}, 可读性评分: {best_score}")
        hex_log.append("[=] 所有编码尝试结果:")
        for enc, score, _ in all_results:
            hex_log.append(f"    {enc:<10} → Score: {score}")

    def parse_file():
        path, _ = QFileDialog.getOpenFileName(None, "选择HEX文本文件", "", "Text Files (*.txt *.log *.hex)")
        if not path: return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                hex_input.setPlainText(content)
                hex_log.append(f"[+] 文件导入成功: {os.path.basename(path)}")
        except Exception as e:
            hex_log.append(f"[!] 读取失败: {e}")

    def manual_decode():
        content = hex_input.toPlainText()
        if not content.strip():
            hex_log.append("[!] 请输入HEX字符串")
            return
        raw_bytes = extract_clean_bytes(content)
        enc = encoding_box.currentText()
        try:
            decoded = raw_bytes.decode(enc, errors="replace")
            hex_result.setPlainText(decoded)
            hex_log.append(f"[+] 使用手动编码 {enc} 解码成功")
        except Exception as e:
            hex_log.append(f"[!] 解码失败: {e}")
            hex_result.clear()

    def save_result():
        text = hex_result.toPlainText()
        if not text.strip():
            QMessageBox.warning(None, "提示", "没有内容可保存")
            return
        path, _ = QFileDialog.getSaveFileName(None, "保存还原结果", "hex_output.txt", "Text Files (*.txt)")
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text)
                hex_log.append(f"[+] 结果已保存到: {path}")
            except Exception as e:
                hex_log.append(f"[!] 保存失败: {e}")

    def clear_all():
        hex_input.clear()
        hex_log.clear()
        hex_result.clear()

    # 布局构建
    h1 = QHBoxLayout()
    h1.addWidget(QPushButton("📂 选择HEX文件", clicked=parse_file))
    h1.addWidget(QPushButton("🧠 最优解码", clicked=parse_input))
    h1.addWidget(QLabel("选择编码:"))
    h1.addWidget(encoding_box)
    h1.addWidget(QPushButton("解析HEX", clicked=manual_decode))
    h1.addWidget(QPushButton("保存结果", clicked=save_result))
    h1.addWidget(QPushButton("清空输出", clicked=clear_all))

    layout.addLayout(h1)
    layout.addWidget(QLabel("HEX粘贴区:"))
    layout.addWidget(hex_input, 2)
    layout.addWidget(QLabel("日志输出:"))
    layout.addWidget(hex_log, 1)
    layout.addWidget(QLabel("还原文本:"))
    layout.addWidget(hex_result, 2)

    return tab
