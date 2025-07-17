from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTextEdit


def create_usage_tab():
    tab = QWidget()
    layout = QVBoxLayout(tab)
    text = QTextEdit()
    text.setReadOnly(True)
    text.setPlainText("""工具简介:
本工具用于模拟固件签名区域被破坏的情景，测试 Secure Boot 和 OTA 安全升级机制的鲁棒性，并支持组件漏洞导出与 HEX 文件还原。

支持功能模块:
1. 固件签名区域识别与篡改（支持 bin、dtb、imx、zip）
2. 文件差异比较（原始 vs 篡改）
3. 签名格式解析（支持 DER/PEM/PKCS7）
4. Dependency-Track 漏洞提取与导出 CSV
5. HEX 文件智能还原（自动判断 bin/json/txt 格式）

使用说明：
🧬 固件篡改页：
- 导入目标文件，选择篡改区域与模式（flip / zero / random）
- 可同时处理 ZIP 中多个固件
- 自动识别签名区域，生成新文件并记录改动

🧪 文件对比页：
- 比较原始和篡改文件字节差异（最多显示前20条）
- 支持快速差异验证

🔐 签名解析页：
- 自动识别 DER / PEM / PKCS7 格式证书
- 提取为 PEM 并解析 subject / issuer / serial

🛡️ 漏洞提取页：
- 填写 DTrack 地址、API Key 和 UUID
- 可导出组件漏洞表（含组件名、CVE ID、CVSS分数等）

📦 HEX解析页：
- 支持输入 dump.txt / log / hex 文件
- 自动提取有效字节、还原 UTF-8 文本
- 自动判断是否是 JSON/BIN/TXT 并支持保存

建议事项：
- 请确保 openssl 已正确安装并在 PATH 中
- 建议先在测试环境使用，避免破坏真实生产固件
""")
    layout.addWidget(text)
    return tab
