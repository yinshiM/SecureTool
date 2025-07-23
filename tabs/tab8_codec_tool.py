import base64
import urllib.parse
from qfluentwidgets import (
    LineEdit, PushButton, TextEdit, SimpleCardWidget,
    TitleLabel, BodyLabel
)
from PyQt5.QtWidgets import QVBoxLayout, QHBoxLayout


def create_codec_tab():
    card = SimpleCardWidget()
    layout = QVBoxLayout(card)
    layout.setContentsMargins(30, 20, 30, 20)
    layout.setSpacing(12)

    layout.addWidget(TitleLabel("常用编解码工具"))

    input_box = LineEdit()
    input_box.setPlaceholderText("输入需要处理的字符串")
    output_box = TextEdit()
    output_box.setReadOnly(True)

    row = QHBoxLayout()
    btn_b64_enc = PushButton("Base64编码")
    btn_b64_dec = PushButton("Base64解码")
    btn_url_enc = PushButton("URL编码")
    btn_url_dec = PushButton("URL解码")
    btn_clear = PushButton("清空")

    row.addWidget(btn_b64_enc)
    row.addWidget(btn_b64_dec)
    row.addWidget(btn_url_enc)
    row.addWidget(btn_url_dec)
    row.addWidget(btn_clear)

    layout.addWidget(BodyLabel("输入文本:"))
    layout.addWidget(input_box)
    layout.addLayout(row)
    layout.addWidget(BodyLabel("结果输出:"))
    layout.addWidget(output_box)

    def set_output(text):
        output_box.setPlainText(text)

    def safe_base64_decode():
        text = input_box.text().strip()
        if not text:
            set_output("[!] 输入为空")
            return
        try:
            decoded = base64.b64decode(text.encode())
            set_output(decoded.decode(errors="ignore"))
        except Exception as e:
            set_output(f"[!] 解码失败: {str(e)}")

    btn_b64_enc.clicked.connect(lambda: set_output(base64.b64encode(input_box.text().encode()).decode()))
    btn_b64_dec.clicked.connect(safe_base64_decode)
    btn_url_enc.clicked.connect(lambda: set_output(urllib.parse.quote(input_box.text())))
    btn_url_dec.clicked.connect(lambda: set_output(urllib.parse.unquote(input_box.text())))
    btn_clear.clicked.connect(lambda: (input_box.clear(), output_box.clear()))

    return card
