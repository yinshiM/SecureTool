import base64
import urllib.parse
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
    QPushButton, QLineEdit, QMessageBox
)


def create_codec_tab():
    tab = QWidget()
    layout = QVBoxLayout(tab)

    input_text = QTextEdit()
    input_text.setPlaceholderText("输入待编解码的文本")
    output_text = QTextEdit()
    output_text.setPlaceholderText("输出结果")
    output_text.setReadOnly(True)

    def show_result(result):
        output_text.setPlainText(result)

    def encode_base64():
        try:
            text = input_text.toPlainText().encode('utf-8')
            result = base64.b64encode(text).decode()
            show_result(result)
        except Exception as e:
            show_result(f"[Base64 编码错误] {e}")

    def decode_base64():
        try:
            text = input_text.toPlainText().strip()
            result = base64.b64decode(text).decode('utf-8', errors='replace')
            show_result(result)
        except Exception as e:
            show_result(f"[Base64 解码错误] {e}")

    def encode_url():
        try:
            result = urllib.parse.quote(input_text.toPlainText())
            show_result(result)
        except Exception as e:
            show_result(f"[URL 编码错误] {e}")

    def decode_url():
        try:
            result = urllib.parse.unquote(input_text.toPlainText())
            show_result(result)
        except Exception as e:
            show_result(f"[URL 解码错误] {e}")

    def encode_ascii():
        try:
            result = ' '.join(f'{ord(c):02x}' for c in input_text.toPlainText())
            show_result(result)
        except Exception as e:
            show_result(f"[ASCII 编码错误] {e}")

    def decode_ascii():
        try:
            hex_str = input_text.toPlainText().replace(" ", "")
            bytes_data = bytes.fromhex(hex_str)
            result = bytes_data.decode('utf-8', errors='replace')
            show_result(result)
        except Exception as e:
            show_result(f"[ASCII 解码错误] {e}")

    def clear_all():
        input_text.clear()
        output_text.clear()

    # 布局
    btn_row1 = QHBoxLayout()
    btn_row1.addWidget(QPushButton("Base64 编码", clicked=encode_base64))
    btn_row1.addWidget(QPushButton("Base64 解码", clicked=decode_base64))

    btn_row2 = QHBoxLayout()
    btn_row2.addWidget(QPushButton("URL 编码", clicked=encode_url))
    btn_row2.addWidget(QPushButton("URL 解码", clicked=decode_url))

    btn_row3 = QHBoxLayout()
    btn_row3.addWidget(QPushButton("ASCII 编码", clicked=encode_ascii))
    btn_row3.addWidget(QPushButton("ASCII 解码", clicked=decode_ascii))

    btn_clear = QPushButton("清除全部", clicked=clear_all)

    layout.addWidget(QLabel("输入区域:"))
    layout.addWidget(input_text)
    layout.addLayout(btn_row1)
    layout.addLayout(btn_row2)
    layout.addLayout(btn_row3)
    layout.addWidget(QLabel("输出区域:"))
    layout.addWidget(output_text)
    layout.addWidget(btn_clear)

    return tab
