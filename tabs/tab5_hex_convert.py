import os, re, json
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QLineEdit, QFileDialog
)


def create_hex_tab():
    tab = QWidget()
    layout = QVBoxLayout(tab)
    log_output = QTextEdit()
    log_output.setReadOnly(True)
    result_output = QTextEdit()
    result_output.setReadOnly(True)
    hex_file_input = QLineEdit()
    hex_file_input.setPlaceholderText("请选择包含 hex 字节的文本文件")

    hex_bytes = []
    format_guess = "txt"  # 默认猜测为文本

    def log(msg):
        log_output.append(msg)

    def guess_format(decoded_text: str, raw_bytes: bytes) -> str:
        try:
            json.loads(decoded_text)
            return "json"
        except:
            pass
        if raw_bytes.startswith(b'\x7fELF'):
            return "bin"
        if raw_bytes.startswith(b'PK\x03\x04') or raw_bytes.startswith(b'\x50\x4B\x03\x04'):
            return "zip"
        if raw_bytes.startswith(b'\x89PNG'):
            return "png"
        printable_ratio = sum(32 <= b < 127 for b in raw_bytes) / max(1, len(raw_bytes))
        if printable_ratio > 0.95:
            return "txt"
        return "bin"

    def parse_hex_file():
        nonlocal hex_bytes, format_guess
        path = hex_file_input.text().strip()
        if not os.path.isfile(path):
            log("[!] 文件无效")
            return
        log(f"[*] 处理文件: {path}")
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            hex_bytes = []
            for line in lines:
                segments = re.findall(r'(?:\b[0-9a-fA-F]{2}\b(?:\s+|$)){4,}', line)
                for seg in segments:
                    hex_bytes.extend(re.findall(r'[0-9a-fA-F]{2}', seg))
            raw_bytes = bytes(int(b, 16) for b in hex_bytes)
            clean_bytes = bytes(b for b in raw_bytes if b >= 0x20 or b in (0x0A, 0x0D))
            try:
                text = clean_bytes.decode("utf-8", errors="ignore")
            except:
                text = clean_bytes.decode("latin1")
            result_output.setPlainText(text)
            format_guess = guess_format(text, raw_bytes)
            log(f"[+] 提取 {len(hex_bytes)} 字节，猜测格式为: {format_guess}")
        except Exception as e:
            log(f"[!] 解析失败: {e}")

    def save_result():
        if not hex_bytes:
            log("[!] 当前无内容可保存")
            return
        orig_path = hex_file_input.text().strip()
        ext = format_guess
        save_filter = "All files (*.*)"
        default_name = f"output.{ext}"
        if ext == "json":
            save_filter = "JSON files (*.json)"
        elif ext == "bin":
            save_filter = "Binary files (*.bin)"
        elif ext == "txt":
            save_filter = "Text files (*.txt)"
        elif ext == "zip":
            save_filter = "ZIP files (*.zip)"
        elif ext == "png":
            save_filter = "PNG images (*.png)"

        out_path, _ = QFileDialog.getSaveFileName(tab, "保存还原文件", default_name, save_filter)
        if not out_path:
            log("[!] 用户取消保存")
            return

        try:
            if ext in ["bin", "zip", "png"]:
                raw = bytes(int(b, 16) for b in hex_bytes)
                with open(out_path, 'wb') as f:
                    f.write(raw)
            else:
                text = result_output.toPlainText()
                with open(out_path, 'w', encoding='utf-8') as f:
                    f.write(text)
            log(f"[+] 成功保存为: {out_path}")
        except Exception as e:
            log(f"[!] 保存失败: {e}")

    btn_browse = QPushButton("选择HEX文件")
    btn_browse.clicked.connect(
        lambda: hex_file_input.setText(
            QFileDialog.getOpenFileName(tab, '选择 HEX 文件', '', 'Text files (*.txt *.log *.hex *.json *.bin)')[0])
    )

    btn_parse = QPushButton("解析并还原文本")
    btn_parse.clicked.connect(parse_hex_file)

    btn_clear = QPushButton("清除日志")
    btn_clear.clicked.connect(lambda: (log_output.clear(), result_output.clear()))

    btn_save = QPushButton("保存还原结果")
    btn_save.clicked.connect(save_result)

    top_row = QHBoxLayout()
    top_row.addWidget(QLabel("文件路径:"))
    top_row.addWidget(hex_file_input)
    top_row.addWidget(btn_browse)
    top_row.addWidget(btn_parse)
    top_row.addWidget(btn_clear)
    top_row.addWidget(btn_save)

    layout.addLayout(top_row)
    layout.addWidget(QLabel("日志输出:"))
    layout.addWidget(log_output)
    layout.addWidget(QLabel("还原文本:"))
    layout.addWidget(result_output)

    return tab
