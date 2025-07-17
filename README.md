# Tamper-Tools 固件篡改与安全评估工具

## 🧩 项目简介

Tamper-Tools 是一个用于安全测试的多功能图形界面工具，主要用于模拟固件签名破坏、对比差异、分析证书信息、提取 SBOM 漏洞信息，以及从
HEX dump 中恢复原始文件。

本工具适用于测试 Secure Boot、OTA 升级机制、Dependency-Track SBOM 合规性、安全证书分析等场景。

---

## 🚀 功能特点

- ✅ **固件签名区域识别与篡改**
    - 自动检测签名区域（模拟 binwalk）
    - 支持 flip / zero / random 篡改模式
    - 支持 zip 包递归处理固件文件

- ✅ **文件差异对比**
    - 原始与篡改文件 byte 级差异分析
    - 显示最多 20 条差异项

- ✅ **签名解析**
    - 支持 X.509 / PEM / PKCS7 证书格式解析
    - 提取证书为 PEM 格式并展示 issuer/subject

- ✅ **组件漏洞提取**
    - 支持对接 Dependency-Track API
    - 自动导出组件漏洞为 CSV 文件

- ✅ **HEX Dump 文件还原**
    - 自动提取十六进制字节并重构文本内容
    - 智能识别是否为 JSON / BIN / TXT
    - 支持还原为原始文件并保存

---

## 📦 安装与运行

### 依赖环境

- Python 3.6+
- PyQt5
- requests
- 可选模块：apkverify（用于解析APK签名）

### 安装依赖

```bash
pip install -r requirements.txt
