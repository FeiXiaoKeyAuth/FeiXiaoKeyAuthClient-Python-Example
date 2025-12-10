import requests
import json
import time
import uuid
import hashlib
import threading
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


# ============================================================
# 配置区域开始 请从作者后台 软件管理 操作按钮 那边获取相应配置 Py就是复制Python配置 C++就是复制C++配置
# ============================================================

# Python配置
API_URL = "http://127.0.0.1:8080"
AUTHOR_ID = 31
SOFTWARE_ID = 22
SECRET_KEY = "3ef3f0ce16e92d0ad526fc7d24bcf1d3" # Hex
VERSION = "1.0111111111111111111111"

# 安全配置
CRYPTO_TYPE = "AES"
USE_SIGNATURE = True

# RSA公钥
PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwL1HFzFAt1ar9jF/Q1VQ
40A+byJh/tjekJUBgOV6CpOinSYVI2LEVq6aP8y17Qr9OFafdq69Awkx7ceueYcA
uxlwuMa9/7vKWcMu4kKEcth4Kuec1KNGzCfbWGO/dszQCFX2E0lfxUCB6REcF7sh
ue5KitjIkcd07XWvPa6hR7qlW7nTMRWvCB0B812c89F3/2u42OgP57KDGjuKnZHm
BoJvttFkUI4VsBFMYrbjfNBuUaTWMQXZRlseyKdp9jQtQ653euXoZroQSooURA+f
/0jqxQ7Zk2OjYK6rIkP5SX+bMAM0h7qq/w76EbwQsbF9RuSJz0857+fpbKZUiU0R
LQIDAQAB
-----END PUBLIC KEY-----"""


# ============================================================
# 配置区域结束
# ============================================================


# ============================================================
# KeyAuth Python 客户端实现
# ============================================================

class KeyAuthClient:
    def __init__(self):
        self.session_id = ""
        self.token = ""
        self.secret_key = bytes.fromhex(SECRET_KEY)
        self.hwid = self._get_hwid()

        # RSA
        self.rsa_key = RSA.import_key(PUBLIC_KEY_PEM)

        self.running = False
        self.thread = None

        print(f"   [验证] KeyAuth 初始化完成 (HWID: {self.hwid})")

    # ------------------------------
    # HWID（MAC → MD5）
    # ------------------------------
    def _get_hwid(self):
        try:
            mac = uuid.getnode()
            h = hashlib.md5()
            h.update(mac.to_bytes(6, "big"))
            return h.hexdigest()
        except:
            return "unknown_hwid"

    def _timestamp(self):
        return int(time.time())

    def _nonce(self):
        return uuid.uuid4().hex

    # ------------------------------
    # 加密（AES / PLAIN）
    # ------------------------------
    def _encrypt_payload(self, data):
        json_str = json.dumps(data, separators=(",", ":"))

        # PLAIN 模式
        if CRYPTO_TYPE.upper() == "PLAIN":
            return json_str.encode().hex(), ""

        # AES CBC
        iv = uuid.uuid4().bytes[:16]
        cipher = AES.new(self.secret_key, AES.MODE_CBC, iv)
        enc = cipher.encrypt(pad(json_str.encode(), AES.block_size))
        return enc.hex(), iv.hex()

    # ------------------------------
    # 解密（AES / PLAIN）
    # ------------------------------
    def _decrypt_payload(self, hex_data, hex_iv):
        if CRYPTO_TYPE.upper() == "PLAIN":
            raw = bytes.fromhex(hex_data)
            return json.loads(raw.decode())

        enc = bytes.fromhex(hex_data)
        iv = bytes.fromhex(hex_iv)
        cipher = AES.new(self.secret_key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(enc), AES.block_size)
        return json.loads(decrypted.decode())

    # ------------------------------
    # RSA 验签（可关闭）
    # ------------------------------
    def _verify_signature(self, data_hex, signature_hex):
        if not USE_SIGNATURE:
            return True

        try:
            raw = bytes.fromhex(data_hex)
            h = SHA256.new(raw)
            sig = bytes.fromhex(signature_hex)
            pkcs1_15.new(self.rsa_key).verify(h, sig)
            return True
        except:
            return False

    # ------------------------------
    # 通用请求
    # ------------------------------
    def send_request(self, endpoint, inner):

        inner["timestamp"] = self._timestamp()
        nonce = self._nonce()
        inner["nonce"] = nonce

        data_hex, iv_hex = self._encrypt_payload(inner)

        payload = {
            "author_id": AUTHOR_ID,
            "software_id": SOFTWARE_ID,
            "data": data_hex,
            "iv": iv_hex,
            "signature": "",
        }

        try:
            r = requests.post(API_URL + endpoint, json=payload, timeout=10)
            res_json = r.json()

            # 登录失败（后端返回 error）
            if "error" in res_json:
                print("   [服务器错误]", res_json["error"])
                return None

            # 必须有 data
            if "data" not in res_json:
                print("   [协议错误] 服务端未返回 data 字段，实际返回:", res_json)
                return None

            # 验签
            if USE_SIGNATURE:
                if not self._verify_signature(res_json["data"], res_json.get("sign", "")):
                    print("   [安全警告] 签名校验失败！")
                    return None

            # 解密业务数据
            decrypted = self._decrypt_payload(res_json["data"], res_json.get("iv", ""))

            # Nonce 防重放
            if decrypted.get("nonce") != nonce:
                print("   [严重警告] Nonce 不匹配（重放攻击）")
                sys.exit(1)

            return decrypted

        except Exception as e:
            print("   [网络错误]", e)
            return None

    # ------------------------------
    # 登录（支持公告、版本更新、下载链接、到期时间）
    # ------------------------------
    def login(self, license_key):
        req = {
            "license": license_key,
            "hwid": self.hwid,
            "version": VERSION,
        }

        res = self.send_request("/api/client/login", req)
        if not res:
            return False

        self.session_id = res.get("session_id", "")
        self.token = res.get("token", "")

        print("   [验证] 登录成功！")

        # 公告
        if "announcement" in res:
            print("   [公告]", res["announcement"])

        # 版本检查
        cloud_ver = res.get("latest_version")
        if cloud_ver:
            if cloud_ver != VERSION:
                print(f"   [更新] 有新版本：{VERSION} → {cloud_ver}")
                if "download_url" in res:
                    print("   [更新] 下载链接:", res["download_url"])
            else:
                print("   [更新] 当前已是最新版本")

        # 到期时间
        if "expiry" in res:
            dt = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(res["expiry"]))
            print("   [到期时间]", dt)

        return True

    # ------------------------------
    # 获取远程变量
    # ------------------------------
    def get_var(self, key):
        req = {"session_id": self.session_id, "var_key": key}
        res = self.send_request("/api/client/get_var", req)
        return res.get("var_value", "") if res else ""

    # ------------------------------
    # 心跳（后台自动刷新 token）
    # ------------------------------
    def _heartbeat_loop(self, interval):
        while self.running:
            req = {"session_id": self.session_id, "token": self.token}
            res = self.send_request("/api/client/heartbeat", req)

            if not res:
                print("   [心跳] 失败，停止心跳")
                break

            next_token = res.get("next_token")
            if next_token == self.token:
                print("   [严重警告] Token 未刷新（重放攻击）")
                break

            self.token = next_token
            print("   [心跳] OK")

            time.sleep(interval)

    def start_keep_alive(self, interval_ms=60000):
        if self.running:
            return
        self.running = True
        interval = interval_ms / 1000
        self.thread = threading.Thread(target=self._heartbeat_loop, args=(interval,), daemon=True)
        self.thread.start()

    def stop_keep_alive(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)


# ============================================================
# 主入口
# ============================================================

if __name__ == "__main__":
    client = KeyAuthClient()

    key = input("   [验证] 请输入卡密：")

    if client.login(key):

        v = client.get_var("test")
        print("   [远程变量] =", v)

        client.start_keep_alive(6000)

        input("按回车退出...")
        client.stop_keep_alive()

    else:
        print("   [验证] 登录失败")
