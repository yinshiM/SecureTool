# SecureTool 安全测试工具

## 项目简介

本工具用于模拟固件签名区域被破坏的情景，可用于测试安全启动（Secure Boot）机制的有效性。安全升级机制有效性。
支持处理多种格式的固件文件，包括.bin、.dtb、.imx和.zip（包含上述格式文件）。

## 功能特点

- **自动识别签名区域**：使用Python工具扫描固件，自动识别签名区域
- **多种篡改模式**：支持位取反(flip)、清零(zero)和随机(random)三种篡改方式
- **递归处理**：支持处理ZIP压缩包内的固件文件
- **差异比较**：自动比较篡改前后的文件差异，验证篡改效果
- **图形界面**：提供友好的GUI操作界面

## 使用方法

1. 点击"选择固件文件"，导入需要篡改的固件
2. 选择篡改模式，设置篡改次数
3. 点击"开始篡改"按钮
4. 程序会自动识别签名区域(或默认使用文件尾部区域)，并进行篡改

## 篡改模式说明

- **flip(位取反)**：将目标字节每一位都取反
- **zero(清零)**：将目标字节修改为0x00
- **random(随机)**：将目标字节随机更改为任意值

## 环境要求

- Python 3.6+
- GUI依赖库：Pyqt5
- 打包命令：`python -m PyInstaller -F -w -n TamperTool tamperTools.py -i tamper.ico --onefile`

## 注意事项

- 请确保系统已安装binwalk和cmp工具
- 建议对测试样本操作，避免破坏原始数据
- 篡改后的文件会自动保存，文件名包含时间戳
