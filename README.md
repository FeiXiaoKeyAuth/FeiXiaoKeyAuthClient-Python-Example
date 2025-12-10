# 🔐 Python Authentication Client Example
**AES 加密 · RSA 签名验证 · HWID 绑定 · 心跳 · 远程变量 · 会话管理**

本项目示例展示了如何使用 Python 构建一个安全、可扩展的软件授权 / 验证客户端。
整个流程与 C++ 客户端保持一致，包括通信加密、RSA 验签、Token 刷新、Nonce 重放保护、心跳保活等。

该示例中的逻辑包括：

- ✔ AES-CBC 数据加密（PKCS7 Padding）  
- ✔ RSA-SHA256 服务端签名验证  
- ✔ requests HTTP 请求  
- ✔ HWID 绑定（MAC → MD5）
- ✔ 卡密登录  
- ✔ 心跳保持（Keep-Alive）  
- ✔ 远程变量（后台可热更新）  
- ✔ 版本检查 / 公告  
- ✔ 可扩展 API Framework

---

# 📦 功能特性

### 🔐 加密通信  
所有请求使用 AES-CBC 加密。  
响应采用 RSA-SHA256 验签，确保数据未被篡改。

### 🖥 HWID 绑定  
默认使用：
- 网卡 MAC → MD5  

可根据需求扩展为更多硬件指纹。

### 🌐 API 封装  
内置常用接口：

| 接口名 | 说明 |
|-------|------|
| `login(license)` | 卡密登录 |
| `get_var(key)` | 获取远程变量 |
| `Heartbeat()` | 心跳包 |
| `start_keep_alive()` | 自动心跳线程 |
| `stop_keep_alive()` | 停止心跳线程 |


### 🧵 心跳线程  
可后台自动保持 Token 刷新，避免卡密掉线。

---

# ⚙️ 配置说明

请修改在 `client.py` 顶部配置，他可以在作者后台对应软件位获取：

---


## 📝 License & EULA

- **License**: 本项目遵循 **MIT License**。详见 [LICENSE](LICENSE) 文件。  
- **EULA (最终用户许可协议)**: 使用本软件即视为你同意 [EULA.md](EULA.md) 中的条款，禁止逆向、破解、绕过验证等。  

> **注意**：本 License 允许商业使用、源码修改与再分发；但 **EULA 禁止任何形式的逆向工程、破解、篡改或绕过授权机制。**


---

#  ⭐ 鸣谢

OpenSSL

Curl

nlohmann/json

VMProtect

skCrypt

---