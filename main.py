import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QTabWidget
from PyQt5.QtGui import QFont, QIcon

from tabs.tab1_firmware_tamper import create_firmware_tab
from tabs.tab2_file_compare import create_compare_tab
from tabs.tab3_signature_parse import create_signature_tab
from tabs.tab4_vuln_fetch import create_vuln_tab
from tabs.tab5_hex_convert import create_hex_tab
from tabs.tab_usage import create_usage_tab
from tabs.tab6_did_parser import create_did_parser_tab
from tabs.tab7_codec_hash import create_hash_tab


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    app.setFont(QFont('微软雅黑', 10))

    window = QWidget()
    window.setWindowTitle('安全工具 v5.1')
    window.setWindowIcon(QIcon("resources/tamper.ico"))
    window.resize(900, 600)

    tabs = QTabWidget()
    tabs.addTab(create_firmware_tab(), "固件篡改")
    tabs.addTab(create_compare_tab(), "文件对比")
    tabs.addTab(create_signature_tab(), "签名解析")
    tabs.addTab(create_vuln_tab(), "组件漏洞提取")
    tabs.addTab(create_hex_tab(), "HEX解析")
    tabs.addTab(create_did_parser_tab(), "DID解析")
    tabs.addTab(create_hash_tab(), "Hash")
    tabs.addTab(create_usage_tab(), "📖 使用说明")
    layout = QVBoxLayout()
    layout.addWidget(tabs)
    window.setLayout(layout)

    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
