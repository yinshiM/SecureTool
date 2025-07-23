from PyQt5.QtWidgets import QWidget, QVBoxLayout
from qfluentwidgets import (
    SimpleCardWidget, TitleLabel, BodyLabel, TextEdit
)


def create_usage_tab():
    tab = QWidget()
    layout = QVBoxLayout(tab)
    layout.setContentsMargins(30, 20, 30, 20)
    layout.setSpacing(12)

    layout.addWidget(TitleLabel("使用说明"))

    desc = BodyLabel(
        "本工具集成多个安全分析模块，支持固件篡改、文件对比、签名提取、组件漏洞查询、十六进制解析、DID 解码与哈希计算等功能，适用于嵌入式安全与工业协议分析场景。")

    layout.addWidget(desc)

    usage_card = SimpleCardWidget()
    usage_layout = QVBoxLayout(usage_card)
    usage_layout.setContentsMargins(20, 10, 20, 10)
    usage_layout.setSpacing(10)

    usage = TextEdit()
    usage.setReadOnly(True)
    usage.setMinimumHeight(520)
    usage.setPlaceholderText("模块说明...")  # 可选

    usage.setPlainText("""✅ 模块 1 - 固件篡改
- 支持 flip（取反）、zero（清零）、random（随机）三种篡改方式
- 可选择签名区域、非签名区域或全范围进行修改
- 自动识别签名区域（若无法识别默认使用末尾512字节）
- 支持 .bin/.imx/.dtb 文件以及 .zip 封装的固件包

✅ 模块 2 - 文件对比
- 对比两个二进制文件的不同字节
- 显示前20个差异位置，便于分析改动效果

✅ 模块 3 - 签名解析
- 自动提取固件中的证书信息（包括X.509/PEM/PKCS#7）
- 若是APK则尝试解析 META-INF 证书内容
- 可将DER证书自动转为PEM格式输出

✅ 模块 4 - 组件漏洞提取（Dependency-Track）
- 通过 API 拉取指定 UUID 项目的漏洞数据
- 支持导出为 CSV 表格
- 显示每个组件关联的漏洞数量

✅ 模块 5 - HEX解析
- 解析 txt/log/dump 文件中提取连续 HEX 字节
- 可选多种常见编码方式进行解码
- 支持 HEX 粘贴输入
- 自动识别编码并评估可读性评分（高分优先显示）

✅ 模块 6 - DID解析
- 支持从 JSON 文件中提取 value_hex 字段内容
- 自动或指定编码方式解码字节数据
- 解析结果支持导出为 txt 或 CSV
- DID 输出按可读性评分排序显示

使用建议：
- 所有日志窗口支持清空和结果保存
- 推荐使用自动编码识别结合手动切换以提升解码准确率
- 所有导出功能支持 UTF-8 编码
""")

    usage_layout.addWidget(usage)
    layout.addWidget(usage_card)

    return tab
