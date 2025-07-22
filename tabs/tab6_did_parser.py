import os, json, csv, re
from PyQt5.QtWidgets import QFileDialog, QHBoxLayout, QVBoxLayout
from qfluentwidgets import (
    LineEdit, PushButton, ComboBox, TextEdit,
    TitleLabel, BodyLabel, SimpleCardWidget
)

COMMON_ENCODINGS = [
    'utf-8', 'utf-16', 'utf-16le', 'utf-16be',
    'utf-32', 'utf-32le', 'utf-32be',
    'gbk', 'gb2312', 'gb18030',
    'big5', 'latin1', 'ascii'
]


def is_readable(s):
    return sum(1 for c in s if c.isprintable() and c not in '\x00') / len(s) if s else 0


def try_best_decode(byte_data):
    best_score, best_text, best_enc = 0, '', ''
    for enc in COMMON_ENCODINGS:
        try:
            decoded = byte_data.decode(enc)
            score = is_readable(decoded)
            if score > best_score:
                best_score, best_text, best_enc = score, decoded, enc
        except:
            continue
    return best_text.strip(), best_enc, best_score


def create_did_parser_tab():
    card = SimpleCardWidget()
    layout = QVBoxLayout(card)
    layout.setContentsMargins(30, 20, 30, 20)
    layout.setSpacing(10)

    layout.addWidget(TitleLabel("DID解析工具（支持编码识别和导出）"))

    input_path = LineEdit()
    input_path.setPlaceholderText("选择包含 value_hex 的 JSON 文件")

    result_view = TextEdit()
    result_view.setReadOnly(True)

    log_view = TextEdit()
    log_view.setReadOnly(True)

    enc_cb = ComboBox()
    enc_cb.addItem("自动识别编码")
    enc_cb.addItems(COMMON_ENCODINGS)

    parsed_results = []

    def browse_file():
        path, _ = QFileDialog.getOpenFileName(card, "选择 JSON 文件", "", "JSON files (*.json)")
        if path:
            input_path.setText(path)

    def parse_json():
        nonlocal parsed_results
        path = input_path.text().strip()
        if not os.path.isfile(path):
            log_view.append("[!] 文件无效")
            return
        log_view.append(f"[*] 解析文件: {path}")
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            results = []
            for item in data:
                did = item.get('did', '未知ID')
                hexval = item.get('value_hex', '')
                hexbytes = re.findall(r'[0-9a-fA-F]{2}', hexval)
                byte_data = bytes(int(b, 16) for b in hexbytes)
                if enc_cb.currentText() == "自动识别编码":
                    text, enc_used, score = try_best_decode(byte_data)
                else:
                    try:
                        text = byte_data.decode(enc_cb.currentText(), errors='replace').strip()
                        enc_used = enc_cb.currentText()
                        score = is_readable(text)
                    except:
                        text, enc_used, score = '', enc_cb.currentText(), 0
                results.append((did, text, enc_used, score))
            parsed_results = sorted(results, key=lambda x: x[3], reverse=True)
            result_view.clear()
            for did, val, enc_used, score in parsed_results:
                result_view.append(f"DID: {did} | 编码: {enc_used} | 可读性: {score:.2f}")
                result_view.append(f"内容: {val}\n")
            log_view.append(f"[+] 共解析 {len(parsed_results)} 条记录")
        except Exception as e:
            log_view.append(f"[!] 解析失败: {e}")

    def save_results():
        out_path, _ = QFileDialog.getSaveFileName(card, "保存结果", "did_results.txt", "Text Files (*.txt)")
        if not out_path:
            return
        try:
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(result_view.toPlainText())
            log_view.append(f"[+] 结果已保存到: {out_path}")
        except Exception as e:
            log_view.append(f"[!] 保存失败: {e}")

    def export_csv():
        if not parsed_results:
            log_view.append("[!] 没有结果可导出")
            return
        path, _ = QFileDialog.getSaveFileName(card, "导出CSV", "did_results.csv", "CSV Files (*.csv)")
        if not path:
            return
        try:
            with open(path, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                writer.writerow(["DID", "内容", "编码", "可读性评分"])
                for did, val, enc_used, score in parsed_results:
                    writer.writerow([did, val, enc_used, f"{score:.2f}"])
            log_view.append(f"[+] 已导出CSV: {path}")
        except Exception as e:
            log_view.append(f"[!] CSV导出失败: {e}")

    row1 = QHBoxLayout()
    row1.addWidget(BodyLabel("JSON路径:"))
    row1.addWidget(input_path)
    row1.addWidget(PushButton("选择", parent=card))
    row1.itemAt(2).widget().clicked.connect(browse_file)

    row2 = QHBoxLayout()
    row2.addWidget(BodyLabel("解码方式:"))
    row2.addWidget(enc_cb)
    row2.addWidget(PushButton("解析", parent=card))
    row2.addWidget(PushButton("保存", parent=card))
    row2.addWidget(PushButton("导出CSV", parent=card))
    row2.itemAt(2).widget().clicked.connect(parse_json)
    row2.itemAt(3).widget().clicked.connect(save_results)
    row2.itemAt(4).widget().clicked.connect(export_csv)

    layout.addLayout(row1)
    layout.addLayout(row2)
    layout.addWidget(TitleLabel("日志输出"))
    layout.addWidget(log_view)
    layout.addWidget(TitleLabel("解析结果"))
    layout.addWidget(result_view)

    return card
