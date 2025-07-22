import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QFont
from qfluentwidgets import FluentWindow, FluentIcon, setTheme, Theme

from tabs.tab1_firmware_tamper import create_firmware_tab
from tabs.tab2_file_compare import create_compare_tab
from tabs.tab3_signature_parse import create_signature_tab
from tabs.tab4_vuln_fetch import create_vuln_tab
from tabs.tab5_hex_convert import create_hex_tab
from tabs.tab6_did_parser import create_did_parser_tab
from tabs.tab7_codec_hash import create_hash_tab
from tabs.tab8_codec_tool import create_codec_tab


from tabs.tab_usage import create_usage_tab


class MyApp(FluentWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("安全工具 v5.1")
        self.resize(1000, 700)
        self.setFont(QFont("微软雅黑", 10))
        self.init_navigation()

    def init_navigation(self):
        pages = [
            ("固件篡改", FluentIcon.EDIT, create_firmware_tab()),
            ("文件对比", FluentIcon.SYNC, create_compare_tab()),
            ("签名解析", FluentIcon.LEAF, create_signature_tab()),
            ("组件漏洞提取", FluentIcon.SEARCH, create_vuln_tab()),
            ("HEX解析", FluentIcon.IOT, create_hex_tab()),
            ("DID解析", FluentIcon.DEVELOPER_TOOLS, create_did_parser_tab()),
            ("Hash", FluentIcon.FINGERPRINT, create_hash_tab()),
            ("编解码", FluentIcon.CODE, create_codec_tab()),
            ("使用说明", FluentIcon.INFO, create_usage_tab()),
        ]

        for title, icon, widget in pages:
            widget.setObjectName(title)  # 必须设置
            self.addSubInterface(widget, icon, title)


def main():
    app = QApplication(sys.argv)
    setTheme(Theme.AUTO)
    window = MyApp()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
