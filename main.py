import sys
import os
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QFont
from qfluentwidgets import (
    FluentWindow, FluentIcon, Theme, setTheme, qconfig,
    NavigationItemPosition, NavigationToolButton
)

from tabs.tab1_firmware_tamper import create_firmware_tab
from tabs.tab2_file_compare import create_compare_tab
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
            ("组件漏洞提取", FluentIcon.SEARCH, create_vuln_tab()),
            ("HEX解析", FluentIcon.IOT, create_hex_tab()),
            ("DID解析", FluentIcon.DEVELOPER_TOOLS, create_did_parser_tab()),
            ("Hash", FluentIcon.FINGERPRINT, create_hash_tab()),
            ("编解码", FluentIcon.CODE, create_codec_tab()),
            ("使用说明", FluentIcon.INFO, create_usage_tab()),
        ]
        for title, icon, widget in pages:
            widget.setObjectName(title)
            self.addSubInterface(widget, icon, title)

        # 添加切换主题按钮
        theme_button = NavigationToolButton(FluentIcon.CONSTRACT, self)
        theme_button.setToolTip("切换明暗主题")
        theme_button.clicked.connect(self.toggle_theme)  # 仅此处绑定即可
        self.navigationInterface.addWidget(
            routeKey="toggleTheme",
            widget=theme_button,
            position=NavigationItemPosition.BOTTOM
        )

    def toggle_theme(self):
        new_theme = Theme.LIGHT if qconfig.theme == Theme.DARK else Theme.DARK
        setTheme(new_theme)  # 设置主题
        qconfig.theme = new_theme  # 更新配置
        qconfig.save()  # 保存配置


def main():
    app = QApplication(sys.argv)
    setTheme(qconfig.theme)
    window = MyApp()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
