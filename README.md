# TamperTools 固件篡改与安全分析工具

## 项目简介

TamperTools 是一款用于安全启动机制测试与固件分析的多功能工具。提供图形界面，可快速进行二进制篡改、证书提取、HEX与DID解码、SBOM
漏洞分析等功能。

## 功能总览

### ✅ 固件篡改

- 支持 flip、zero、random 多种方式
- 签名区域自动识别
- 可处理 bin、imx、dtb、zip 格式

### ✅ 文件对比

- 显示前20处二进制差异

### ✅ 签名提取

- 支持 PKCS7 / PEM / DER 格式
- 自动转为可读格式并导出

### ✅ SBOM 漏洞提取

- 集成 Dependency-Track 接口
- 支持 UUID 查询并导出漏洞 CSV

### ✅ HEX解析

- 提取 HEX 串并按指定或自动编码解码
- 支持多种格式输入（.txt / .log / 粘贴）
- 可读性评分 + 自动排序

### ✅ DID解析

- 从 JSON 中提取 value_hex 字段
- 自动识别编码并按可读性评分排序输出
- 支持结果导出 TXT / CSV

## 安装依赖

```bash
pip install PyQt5 requests
```

## 打包方式

```
pyinstaller -F -w -i tamper.ico main.py
```

## ✅ 使用建议

- 建议使用 UTF-8 编码的 JSON 文件输入
- 避免对真实生产固件执行篡改操作
- 所有操作日志均可导出或复制